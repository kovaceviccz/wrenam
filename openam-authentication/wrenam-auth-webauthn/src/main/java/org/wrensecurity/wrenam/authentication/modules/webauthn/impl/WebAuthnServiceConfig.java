/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2025 Wren Security. All rights reserved.
 */
package org.wrensecurity.wrenam.authentication.modules.webauthn.impl;

import com.iplanet.sso.SSOException;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.util.Map;
import java.util.Set;
import org.forgerock.openam.core.rest.devices.services.webauthn.WebAuthnService;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;

/**
 * Resolve WebAuthn service configuration used by authentication and registration modules.
 */
public class WebAuthnServiceConfig {

    private static final String USER_ID_KEY = "wrensec-am-auth-webauthn-user-id-attr";

    private static final String DEFAULT_USER_ID_KEY = "entryUUID";

    private static final String USER_DISPLAY_NAME_KEY = "wrensec-am-auth-webauthn-user-display-name-attr";

    private static final String DEFAULT_USER_DISPLAY_NAME_KEY = "cn";

    /**
     * Create WebAuthn service configuration access.
     */
    public WebAuthnServiceConfig() {
    }

    private ServiceConfig getServiceConfig(String realm) throws SMSException, SSOException {
        ServiceConfigManager scm = new ServiceConfigManager(
                AccessController.doPrivileged(AdminTokenAction.getInstance()),
                WebAuthnService.SERVICE_NAME,
                WebAuthnService.SERVICE_VERSION);
        return scm.getOrganizationConfig(realm, null);
    }

    /**
     * Return the configured attribute containing the WebAuthn user handle.
     *
     * @param realm realm containing the configuration
     * @return user handle attribute name
     * @throws SMSException if service configuration cannot be read
     * @throws SSOException if the admin token cannot read service configuration
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">WebAuthn Level 3 &sect;14.6.1</a>
     */
    public String getUserIdAttribute(String realm) throws SMSException, SSOException {
        ServiceConfig config = getServiceConfig(realm);
        Map<String, Set<String>> attrs = config.getAttributes();
        return CollectionHelper.getMapAttr(attrs, USER_ID_KEY, DEFAULT_USER_ID_KEY);
    }

    /**
     * Return the configured attribute containing the user display name.
     *
     * @param realm realm containing the configuration
     * @return user display name attribute name
     * @throws SMSException if service configuration cannot be read
     * @throws SSOException if the admin token cannot read service configuration
     */
    public String getUserDisplayNameAttribute(String realm) throws SMSException, SSOException {
        ServiceConfig config = getServiceConfig(realm);
        Map<String, Set<String>> attrs = config.getAttributes();
        return CollectionHelper.getMapAttr(attrs, USER_DISPLAY_NAME_KEY, DEFAULT_USER_DISPLAY_NAME_KEY);
    }

    /**
     * Normalize a configured relying party origin for WebAuthn origin comparison.
     *
     * @param configuredOrigin configured origin
     * @return normalized origin containing only scheme, host, and optional port
     * @throws WebAuthnCeremonyException if the origin is missing or invalid
     */
    public String normalizeConfiguredOrigin(String configuredOrigin) throws WebAuthnCeremonyException {
        if (configuredOrigin == null || configuredOrigin.isBlank()) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.MISSING_ORIGIN_CONFIG);
        }
        try {
            URI origin = new URI(configuredOrigin.trim());
            if (origin.getScheme() == null || origin.getHost() == null
                    || origin.getPath() != null && !origin.getPath().isEmpty() && !"/".equals(origin.getPath())
                    || origin.getQuery() != null
                    || origin.getFragment() != null) {
                throw new WebAuthnCeremonyException(WebAuthnCeremonyError.INVALID_ORIGIN_CONFIG);
            }
            String scheme = origin.getScheme().toLowerCase();
            StringBuilder normalized = new StringBuilder()
                    .append(scheme)
                    .append("://")
                    .append(origin.getHost().toLowerCase());
            if (origin.getPort() >= 0 && !isDefaultPort(scheme, origin.getPort())) {
                normalized.append(':').append(origin.getPort());
            }
            return normalized.toString();
        } catch (URISyntaxException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.INVALID_ORIGIN_CONFIG, e);
        }
    }

    private boolean isDefaultPort(String scheme, int port) {
        return "https".equals(scheme) && port == 443 || "http".equals(scheme) && port == 80;
    }

}
