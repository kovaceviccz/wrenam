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

import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.config.AMAuthConfigUtils;
import com.sun.identity.authentication.config.AMAuthenticationInstance;
import com.sun.identity.shared.debug.Debug;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Tests for {@link WebAuthnAuthenticationImplementationResolver}.
 */
public class WebAuthnAuthenticationImplementationResolverTest {

    private static final String REALM = "/";
    private static final String USERNAMELESS_ATTRIBUTE = "wrensec-am-auth-webauthn-usernameless";
    private static final String RP_ID_ATTRIBUTE = "wrensec-am-auth-webauthn-rp-id";
    private static final String ORIGIN_ATTRIBUTE = "wrensec-am-auth-webauthn-origin";

    private TestResolver resolver;

    @BeforeMethod
    public void setUp() {
        resolver = new TestResolver();
    }

    @Test
    public void shouldAdvertiseDefaultUsernamelessWebAuthnChain() {
        resolver.defaultChain = "defaultPasskey";
        resolver.namedConfigs.add("fallbackPasskey");
        resolver.namedConfigs.add("defaultPasskey");
        resolver.configs.put("defaultPasskey", chainConfig("defaultPasskeyModule"));
        resolver.configs.put("fallbackPasskey", chainConfig("fallbackPasskeyModule"));
        resolver.instances.put("defaultPasskeyModule", webAuthnInstance(true, "https://am.example.com"));
        resolver.instances.put("fallbackPasskeyModule", webAuthnInstance(true, "https://fallback.example.com"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isTrue();
        assertThat(implementation.getAuthnChain()).isEqualTo("defaultPasskey");
    }

    @Test
    public void shouldAdvertiseFirstSortedFallbackUsernamelessWebAuthnChain() {
        resolver.defaultChain = "passwordLogin";
        resolver.namedConfigs.add("zPasskey");
        resolver.namedConfigs.add("passwordLogin");
        resolver.namedConfigs.add("aPasskey");
        resolver.configs.put("passwordLogin", chainConfig("dataStore"));
        resolver.configs.put("zPasskey", chainConfig("zPasskeyModule"));
        resolver.configs.put("aPasskey", chainConfig("aPasskeyModule"));
        resolver.instances.put("dataStore", instance("DataStore", true));
        resolver.instances.put("zPasskeyModule", webAuthnInstance(true, "https://z.example.com"));
        resolver.instances.put("aPasskeyModule", webAuthnInstance(true, "https://a.example.com"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isTrue();
        assertThat(implementation.getAuthnChain()).isEqualTo("aPasskey");
    }

    @Test
    public void shouldNotAdvertiseAccountBoundWebAuthnChain() {
        resolver.defaultChain = "accountBound";
        resolver.namedConfigs.add("accountBound");
        resolver.configs.put("accountBound", chainConfig("accountBoundModule"));
        resolver.instances.put("accountBoundModule", webAuthnInstance(false, "https://am.example.com"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isFalse();
        assertThat(implementation.getAuthnChain()).isNull();
    }

    @Test
    public void shouldRequireWebAuthnAsFirstChainModule() {
        resolver.defaultChain = "twoFactor";
        resolver.namedConfigs.add("twoFactor");
        resolver.configs.put("twoFactor", chainConfig("dataStore", "passkeyModule"));
        resolver.instances.put("dataStore", instance("DataStore", true));
        resolver.instances.put("passkeyModule", webAuthnInstance(true, "https://am.example.com"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isFalse();
    }

    @Test
    public void shouldLetChainOptionsOverrideModuleUsernamelessConfiguration() {
        resolver.defaultChain = "passkey";
        resolver.namedConfigs.add("passkey");
        resolver.configs.put("passkey", chainConfigWithOptions("passkeyModule",
                USERNAMELESS_ATTRIBUTE + "=false"));
        resolver.instances.put("passkeyModule", webAuthnInstance(true, "https://am.example.com"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isFalse();
    }

    @Test
    public void shouldNotAdvertiseInvalidOriginConfiguration() {
        resolver.defaultChain = "passkey";
        resolver.namedConfigs.add("passkey");
        resolver.configs.put("passkey", chainConfig("passkeyModule"));
        resolver.instances.put("passkeyModule", webAuthnInstance(true, "https://am.example.com/auth"));

        WebAuthnAuthenticationImplementation implementation = resolver.resolve(REALM);

        assertThat(implementation.isEnabled()).isFalse();
    }

    private Map<String, Set<String>> chainConfig(String... modules) {
        StringBuilder xml = new StringBuilder("<AttributeValuePair>");
        for (String module : modules) {
            xml.append("<Value>").append(module).append(" REQUIRED</Value>");
        }
        xml.append("</AttributeValuePair>");
        return singletonMap(AMAuthConfigUtils.ATTR_NAME, singleton(xml.toString()));
    }

    private Map<String, Set<String>> chainConfigWithOptions(String module, String options) {
        return singletonMap(AMAuthConfigUtils.ATTR_NAME,
                singleton("<AttributeValuePair><Value>" + module + " REQUIRED " + options
                        + "</Value></AttributeValuePair>"));
    }

    private AMAuthenticationInstance webAuthnInstance(boolean usernameless, String origin) {
        AMAuthenticationInstance instance = instance("WebAuthnAuthentication", usernameless);
        Map<String, Set<String>> attributes = new LinkedHashMap<>();
        attributes.put(USERNAMELESS_ATTRIBUTE, singleton(Boolean.toString(usernameless)));
        attributes.put(RP_ID_ATTRIBUTE, singleton("am.example.com"));
        attributes.put(ORIGIN_ATTRIBUTE, singleton(origin));
        given(instance.getAttributeValues()).willReturn(attributes);
        return instance;
    }

    private AMAuthenticationInstance instance(String type, boolean usernameless) {
        AMAuthenticationInstance instance = mock(AMAuthenticationInstance.class);
        given(instance.getType()).willReturn(type);
        if (!"WebAuthnAuthentication".equals(type)) {
            given(instance.getAttributeValues()).willReturn(singletonMap(USERNAMELESS_ATTRIBUTE,
                    singleton(Boolean.toString(usernameless))));
        }
        return instance;
    }

    private static final class TestResolver extends WebAuthnAuthenticationImplementationResolver {
        private final Map<String, AMAuthenticationInstance> instances = new LinkedHashMap<>();
        private final Set<String> namedConfigs = new LinkedHashSet<>();
        private final Map<String, Map<String, Set<String>>> configs = new LinkedHashMap<>();
        private String defaultChain;

        private TestResolver() {
            super(mock(SSOToken.class), mock(Debug.class));
        }

        @Override
        AuthenticationManager createAuthenticationManager(String realm) {
            return instances::get;
        }

        @Override
        String getRealmDefaultAuthenticationChain(String realm) {
            return defaultChain;
        }

        @Override
        Set<String> getAllNamedConfigs(String realm) {
            return namedConfigs;
        }

        @Override
        Map<String, Set<String>> getNamedConfig(String chain, String realm) {
            return configs.getOrDefault(chain, singletonMap(AMAuthConfigUtils.ATTR_NAME,
                    singleton("<AttributeValuePair></AttributeValuePair>")));
        }
    }
}
