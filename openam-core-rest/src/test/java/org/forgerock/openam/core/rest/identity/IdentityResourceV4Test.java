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
package org.forgerock.openam.core.rest.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.http.routing.Version.version;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.forgerock.util.test.assertj.AssertJPromiseAssert.assertThatPromise;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.service.ConfiguredAuthServices;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.Constants;
import java.util.LinkedHashMap;
import java.util.Map;
import org.forgerock.http.routing.ApiVersionRouterContext;
import org.forgerock.http.routing.Version;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.Requests;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.RestConstants;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class IdentityResourceV4Test {

    private ConfiguredAuthServices configuredAuthServices;

    private IdentityResourceV3 identityResourceV3;

    private IdentityResourceV4 resource;

    private SSOToken ssoToken;

    @BeforeMethod
    public void setUp() {
        configuredAuthServices = mock(ConfiguredAuthServices.class);
        identityResourceV3 = mock(IdentityResourceV3.class);
        ssoToken = mock(SSOToken.class);
        when(configuredAuthServices.getChoiceValues(anyMap())).thenReturn(getAuthenticationConfigurations());
        resource = new IdentityResourceV4(IdentityRestUtils.USER_TYPE,
                null, null, identityResourceV3, configuredAuthServices);
    }

    @Test
    public void shouldPreserveVersionFourUserSchema() throws Exception {
        ActionResponse response = resource.actionCollection(createContext(version(4, 0)),
                Requests.newActionRequest("", RestConstants.SCHEMA)).getOrThrowUninterruptibly();

        assertThat(response.getJsonContent().get("properties").keys()).containsOnly("name");
        verify(configuredAuthServices, never()).getChoiceValues(anyMap());
    }

    @Test
    public void shouldReturnVersionFourOneUserFormSchema() throws Exception {
        when(configuredAuthServices.getChoiceValues(anyMap())).thenAnswer(invocation -> {
            Map<?, ?> environment = invocation.getArgument(0);
            assertThat(environment.get(Constants.ORGANIZATION_NAME)).isEqualTo("/");
            assertThat(environment.get(Constants.SSO_TOKEN)).isSameAs(ssoToken);
            return getAuthenticationConfigurations();
        });

        ActionResponse response = resource.actionCollection(createContext(version(4, 1)),
                Requests.newActionRequest("", RestConstants.SCHEMA)).getOrThrowUninterruptibly();
        JsonValue properties = response.getJsonContent().get("properties");
        String[] propertyNames = {
            "givenName",
            "sn",
            "cn",
            "userPassword",
            "mail",
            "employeeNumber",
            "telephoneNumber",
            "postalAddress",
            "inetUserStatus",
            "iplanet-am-user-account-life",
            "iplanet-am-user-auth-config",
            "iplanet-am-user-alias-list",
            "iplanet-am-user-success-url",
            "iplanet-am-user-failure-url",
            "sunIdentityMSISDNNumber"
        };

        assertThat(properties.keys()).containsOnly(propertyNames);
        for (int i = 0; i < propertyNames.length; i++) {
            assertThat(properties.get(propertyNames[i]).get("propertyOrder").asInteger())
                    .isEqualTo((i + 1) * 100);
        }
        for (String property : new String[] {
            "givenName",
            "sn",
            "cn",
            "userPassword",
            "mail",
            "employeeNumber",
            "telephoneNumber",
            "postalAddress",
            "inetUserStatus",
            "iplanet-am-user-account-life",
            "iplanet-am-user-auth-config"
        }) {
            assertThat(properties.get(property).get("type").asString()).isEqualTo("string");
        }
        for (String property : new String[] {
            "iplanet-am-user-alias-list",
            "iplanet-am-user-success-url",
            "iplanet-am-user-failure-url",
            "sunIdentityMSISDNNumber"
        }) {
            assertThat(properties.get(property).get("type").asString()).isEqualTo("array");
            assertThat(properties.get(property).get("items").get("type").asString()).isEqualTo("string");
        }

        assertThat(properties.get("sn").get("required").asBoolean()).isTrue();
        assertThat(properties.get("cn").get("required").asBoolean()).isTrue();
        assertThat(properties.get("userPassword").get("required").asBoolean()).isTrue();
        assertThat(properties.get("inetUserStatus").get("required").asBoolean()).isTrue();
        assertThat(properties.get("userPassword").get("format").asString()).isEqualTo("password");
        assertThat(properties.get("mail").get("format").asString()).isEqualTo("email");
        assertThat(properties.get("inetUserStatus").get("enum").asList(String.class))
                .containsExactly("Active", "Inactive");
        assertThat(properties.get("iplanet-am-user-auth-config").get("enum").asList(String.class))
                .containsExactly(ISAuthConstants.BLANK, "alpha", "zulu");
    }

    @Test
    public void shouldReturnVersionFourOneUserCreationTemplate() throws Exception {
        ActionResponse response = resource.actionCollection(createContext(version(4, 1)),
                Requests.newActionRequest("", RestConstants.TEMPLATE)).getOrThrowUninterruptibly();
        JsonValue template = response.getJsonContent();

        assertThat(template.keys()).containsOnly(
                "givenName", "sn", "cn", "userPassword", "inetUserStatus");
        assertThat(template.get("givenName").asString()).isEmpty();
        assertThat(template.get("sn").asString()).isEmpty();
        assertThat(template.get("cn").asString()).isEmpty();
        assertThat(template.get("userPassword").asString()).isEmpty();
        assertThat(template.get("inetUserStatus").asString()).isEqualTo("Active");
    }

    @Test
    public void shouldDelegateTemplateActionForVersionFour() throws Exception {
        Context context = createContext(version(4, 0));
        ActionRequest request = Requests.newActionRequest("", RestConstants.TEMPLATE);
        ActionResponse delegatedResponse = mock(ActionResponse.class);
        when(identityResourceV3.actionCollection(context, request)).thenReturn(newResultPromise(delegatedResponse));

        assertThat(resource.actionCollection(context, request).getOrThrowUninterruptibly())
                .isSameAs(delegatedResponse);
    }

    @Test
    public void shouldRejectInvalidAccountExpirationDateOnCreate() {
        Context context = createContext(version(4, 0));
        CreateRequest request = Requests.newCreateRequest("", json(object(
                field("iplanet-am-user-account-life", "12/31/2030 23:59"))));

        assertThatPromise(resource.createInstance(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
        verify(identityResourceV3, never()).createInstance(context, request);
    }

    @Test
    public void shouldRejectImpossibleAccountExpirationDateOnUpdate() {
        Context context = createContext(version(4, 0));
        UpdateRequest request = Requests.newUpdateRequest("", json(object(
                field("iplanet-am-user-account-life", "2030/02/30 23:59:00"))));

        assertThatPromise(resource.updateInstance(context, "demo", request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
        verify(identityResourceV3, never()).updateInstance(context, "demo", request);
    }

    @Test
    public void shouldRejectUnknownAuthenticationConfigurationOnCreate() {
        Context context = createContext(version(4, 0));
        CreateRequest request = Requests.newCreateRequest("", json(object(
                field("iplanet-am-user-auth-config", "missing"))));

        assertThatPromise(resource.createInstance(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
        verify(identityResourceV3, never()).createInstance(context, request);
    }

    @Test
    public void shouldRejectUnknownAuthenticationConfigurationOnUpdate() {
        Context context = createContext(version(4, 0));
        UpdateRequest request = Requests.newUpdateRequest("", json(object(
                field("iplanet-am-user-auth-config", "missing"))));

        assertThatPromise(resource.updateInstance(context, "demo", request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
        verify(identityResourceV3, never()).updateInstance(context, "demo", request);
    }

    @Test
    public void shouldDelegateValidProfileUpdate() throws Exception {
        Context context = createContext(version(4, 0));
        UpdateRequest request = Requests.newUpdateRequest("", json(object(
                field("iplanet-am-user-account-life", "2030/12/31 23:59:00"),
                field("iplanet-am-user-auth-config", "alpha"))));
        ResourceResponse delegatedResponse = mock(ResourceResponse.class);
        when(identityResourceV3.updateInstance(context, "demo", request))
                .thenReturn(newResultPromise(delegatedResponse));

        assertThat(resource.updateInstance(context, "demo", request).getOrThrowUninterruptibly())
                .isSameAs(delegatedResponse);
    }

    private Context createContext(Version version) {
        Context context = mock(Context.class);
        ApiVersionRouterContext versionContext = mock(ApiVersionRouterContext.class);
        RealmContext realmContext = mock(RealmContext.class);
        SSOTokenContext tokenContext = mock(SSOTokenContext.class);
        Realm realm = mock(Realm.class);

        when(context.asContext(ApiVersionRouterContext.class)).thenReturn(versionContext);
        when(versionContext.getResourceVersion()).thenReturn(version);
        when(context.asContext(RealmContext.class)).thenReturn(realmContext);
        when(realmContext.getRealm()).thenReturn(realm);
        when(realm.asPath()).thenReturn("/");
        when(context.containsContext(SSOTokenContext.class)).thenReturn(true);
        when(context.asContext(SSOTokenContext.class)).thenReturn(tokenContext);
        when(tokenContext.getCallerSSOToken()).thenReturn(ssoToken);
        return context;
    }

    private Map<String, String> getAuthenticationConfigurations() {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("zulu", "zulu");
        result.put(ISAuthConstants.BLANK, ISAuthConstants.BLANK);
        result.put("alpha", "alpha");
        return result;
    }

}
