/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security.
 */

package org.forgerock.openam.core.rest.server;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.config.AMAuthConfigUtils;
import com.sun.identity.authentication.config.AMAuthenticationInstance;
import com.sun.identity.authentication.config.AMAuthenticationManager;
import com.sun.identity.authentication.config.AMConfigurationException;
import com.sun.identity.authentication.config.AuthConfigurationEntry;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;

/**
 * Resolves whether the realm has a WebAuthn chain that can start with a discoverable passkey.
 */
class WebAuthnAuthenticationImplementationResolver {

    private static final String AUTH_SERVICE_NAME = "iPlanetAMAuthService";
    private static final String DEFAULT_AUTH_CHAIN_ATTRIBUTE = "iplanet-am-auth-org-config";
    private static final String WEBAUTHN_MODULE_TYPE = "WebAuthnAuthentication";
    private static final String USERNAMELESS_ATTRIBUTE = "wrensec-am-auth-webauthn-usernameless";
    private static final String RP_ID_ATTRIBUTE = "wrensec-am-auth-webauthn-rp-id";
    private static final String ORIGIN_ATTRIBUTE = "wrensec-am-auth-webauthn-origin";

    private final SSOToken token;
    private final Debug debug;

    WebAuthnAuthenticationImplementationResolver(SSOToken token, Debug debug) {
        this.token = token;
        this.debug = debug;
    }

    WebAuthnAuthenticationImplementation resolve(String realm) {
        try {
            AuthenticationManager authenticationManager = createAuthenticationManager(realm);
            String defaultChain = getRealmDefaultAuthenticationChain(realm);
            if (isUsernamelessWebAuthnChain(defaultChain, realm, authenticationManager)) {
                return new WebAuthnAuthenticationImplementation(true, defaultChain);
            }

            List<String> namedChains = new ArrayList<>(getAllNamedConfigs(realm));
            Collections.sort(namedChains);
            for (String chain : namedChains) {
                if (!chain.equals(defaultChain) && isUsernamelessWebAuthnChain(chain, realm, authenticationManager)) {
                    return new WebAuthnAuthenticationImplementation(true, chain);
                }
            }
        } catch (SSOException | SMSException | AMConfigurationException e) {
            if (debug.errorEnabled()) {
                debug.error("Failed resolving WebAuthn authentication implementation for realm " + realm, e);
            }
        }
        return new WebAuthnAuthenticationImplementation();
    }

    AuthenticationManager createAuthenticationManager(String realm) throws AMConfigurationException {
        AMAuthenticationManager authenticationManager = new AMAuthenticationManager(token, realm);
        return authenticationManager::getAuthenticationInstance;
    }

    String getRealmDefaultAuthenticationChain(String realm) throws SMSException, SSOException {
        ServiceConfig serviceConfig =
                new ServiceConfigManager(AUTH_SERVICE_NAME, token).getOrganizationConfig(realm, null);
        if (serviceConfig == null) {
            return null;
        }
        return CollectionHelper.getMapAttr(serviceConfig.getAttributes(), DEFAULT_AUTH_CHAIN_ATTRIBUTE);
    }

    Set<String> getAllNamedConfigs(String realm) throws SMSException, SSOException {
        return AMAuthConfigUtils.getAllNamedConfig(realm, token);
    }

    Map<String, Set<String>> getNamedConfig(String chain, String realm)
            throws SMSException, SSOException, AMConfigurationException {
        return AMAuthConfigUtils.getNamedConfig(chain, realm, token);
    }

    private boolean isUsernamelessWebAuthnChain(String chain, String realm, AuthenticationManager authenticationManager)
            throws SMSException, SSOException, AMConfigurationException {
        if (chain == null || chain.isBlank()) {
            return false;
        }
        List<AuthConfigurationEntry> entries = getAuthConfigurationEntries(chain, realm);
        if (entries.isEmpty()) {
            return false;
        }

        AuthConfigurationEntry firstEntry = entries.get(0);
        AMAuthenticationInstance instance = authenticationManager.getAuthenticationInstance(
                firstEntry.getLoginModuleName());
        if (instance == null || !WEBAUTHN_MODULE_TYPE.equals(instance.getType())) {
            return false;
        }

        return isUsernameless(firstEntry, instance) && hasUsableRelyingPartyConfiguration(firstEntry, instance);
    }

    private List<AuthConfigurationEntry> getAuthConfigurationEntries(String chain, String realm)
            throws SMSException, SSOException, AMConfigurationException {
        Set<String> values = getNamedConfig(chain, realm).get(AMAuthConfigUtils.ATTR_NAME);
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<AuthConfigurationEntry> entries = new ArrayList<>();
        for (Object entry : AMAuthConfigUtils.xmlToAuthConfigurationEntry(values.iterator().next())) {
            if (entry instanceof AuthConfigurationEntry) {
                entries.add((AuthConfigurationEntry) entry);
            }
        }
        return entries;
    }

    private boolean isUsernameless(AuthConfigurationEntry entry, AMAuthenticationInstance instance) {
        Boolean chainOverride = getBooleanOption(entry.getOptions(), USERNAMELESS_ATTRIBUTE);
        if (chainOverride != null) {
            return chainOverride;
        }
        return CollectionHelper.getBooleanMapAttr(instance.getAttributeValues(), USERNAMELESS_ATTRIBUTE, false);
    }

    private boolean hasUsableRelyingPartyConfiguration(AuthConfigurationEntry entry,
            AMAuthenticationInstance instance) {
        Map attributes = instance.getAttributeValues();
        String rpId = getEffectiveStringValue(entry.getOptions(), attributes, RP_ID_ATTRIBUTE);
        String origin = getEffectiveStringValue(entry.getOptions(), attributes, ORIGIN_ATTRIBUTE);
        return rpId != null && !rpId.isBlank() && isValidOrigin(origin);
    }

    private String getEffectiveStringValue(String options, Map attributes, String key) {
        String chainOverride = getStringOption(options, key);
        if (chainOverride != null) {
            return chainOverride;
        }
        return CollectionHelper.getMapAttr(attributes, key);
    }

    private Boolean getBooleanOption(String options, String key) {
        String value = getStringOption(options, key);
        return value == null ? null : Boolean.valueOf(value);
    }

    private String getStringOption(String options, String key) {
        if (options == null || options.isBlank()) {
            return null;
        }
        for (String option : options.split("\\s+")) {
            int separator = option.indexOf('=');
            if (separator <= 0) {
                continue;
            }
            if (key.equals(option.substring(0, separator))) {
                return option.substring(separator + 1);
            }
        }
        return null;
    }

    private boolean isValidOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return false;
        }
        try {
            URI uri = new URI(origin.trim());
            return uri.getScheme() != null && uri.getHost() != null
                    && (uri.getPath() == null || uri.getPath().isEmpty() || "/".equals(uri.getPath()))
                    && uri.getQuery() == null
                    && uri.getFragment() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    interface AuthenticationManager {
        AMAuthenticationInstance getAuthenticationInstance(String moduleName);
    }
}
