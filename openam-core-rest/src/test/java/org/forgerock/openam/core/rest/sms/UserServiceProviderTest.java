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
package org.forgerock.openam.core.rest.sms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.mockito.MockedConstruction;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class UserServiceProviderTest {

    private Context context;

    private Set<String> assignedServices;

    private Set<String> assignableServices;

    private UserServiceProvider provider;

    @BeforeMethod
    public void setUp() {
        assignedServices = Collections.singleton("assignedService");
        assignableServices = Collections.singleton("assignableService");
        context = createContext();
        provider = new UserServiceProvider(mock(Debug.class), mock(AMResourceBundleCache.class),
                Locale.ENGLISH, mock(SmsConsoleServiceNameFilter.class));
    }

    @Test
    public void shouldReturnOnlyTheSelectedUsersAssignableServicesAsCreatable() throws Exception {
        try (MockedConstruction<AMIdentity> identities = createUser();
                MockedConstruction<ServiceSchemaManager> schemas = createSchemas()) {
            JsonValue response = provider.getCreatableTypes(context, "demo");

            assertThat(response.get("result").size()).isEqualTo(1);
            assertThat(response.get("result").get(0).get("_id").asString()).isEqualTo("assignable");
            assertThat(schemas.constructed()).hasSize(1);
        }
    }

    @Test
    public void shouldReturnAssignedAndAssignableServicesAsAvailableTypes() throws Exception {
        try (MockedConstruction<AMIdentity> identities = createUser();
                MockedConstruction<ServiceSchemaManager> schemas = createSchemas()) {
            JsonValue response = provider.getAllTypes(context, "demo");

            assertThat(response.get("result").size()).isEqualTo(2);
            assertThat(response.get("result").get(0).get("_id").asString()).isEqualTo("assigned");
            assertThat(response.get("result").get(1).get("_id").asString()).isEqualTo("assignable");
        }
    }

    @Test
    public void shouldRejectCreationOfAVisibleButUnassignableService() throws Exception {
        try (MockedConstruction<AMIdentity> identities = createUser();
                MockedConstruction<ServiceSchemaManager> schemas = createSchemas()) {
            assertThatThrownBy(() -> provider.create(
                    context, "demo", "visibleButUnassignable", JsonValue.json(JsonValue.object())))
                    .isInstanceOf(NotFoundException.class);

            verify(identities.constructed().get(0), never()).assignService(any(String.class), any());
        }
    }

    @Test
    public void shouldValidateEveryServiceBeforeUnassigningAnyService() throws Exception {
        try (MockedConstruction<AMIdentity> identities = createUser();
                MockedConstruction<ServiceSchemaManager> schemas = createSchemas()) {
            assertThatThrownBy(() -> provider.unassign(
                    context, "demo", Arrays.asList("assigned", "missing")))
                    .isInstanceOf(NotFoundException.class);

            verify(identities.constructed().get(0), never()).unassignService(any(String.class));
        }
    }

    @Test
    public void shouldRejectReadingAnAssignableButUnassignedService() {
        try (MockedConstruction<AMIdentity> identities = createUser();
                MockedConstruction<ServiceSchemaManager> schemas = createSchemas()) {
            assertThatThrownBy(() -> provider.read(context, "demo", "assignable"))
                    .isInstanceOf(NotFoundException.class);
        }
    }

    private MockedConstruction<AMIdentity> createUser() {
        return mockConstruction(AMIdentity.class, (identity, constructionContext) -> {
            when(identity.isExists()).thenReturn(true);
            when(identity.getAssignedServices()).thenReturn(assignedServices);
            when(identity.getAssignableServices()).thenReturn(assignableServices);
        });
    }

    private MockedConstruction<ServiceSchemaManager> createSchemas() {
        return mockConstruction(ServiceSchemaManager.class, (manager, constructionContext) -> {
            String serviceName = (String) constructionContext.arguments().get(0);
            ServiceSchema schema = createSchema(serviceName);
            when(manager.getResourceName()).thenReturn(getResourceId(serviceName));
            when(manager.getUserSchema()).thenReturn(schema);
        });
    }

    private ServiceSchema createSchema(String serviceName) {
        AttributeSchema attribute = mock(AttributeSchema.class);
        when(attribute.getName()).thenReturn("quota");
        when(attribute.getResourceName()).thenReturn("quota");
        when(attribute.getI18NKey()).thenReturn("quota");
        when(attribute.getType()).thenReturn(AttributeSchema.Type.SINGLE);
        when(attribute.getSyntax()).thenReturn(AttributeSchema.Syntax.STRING);
        when(attribute.isOptional()).thenReturn(true);
        when(attribute.getExampleValues()).thenReturn(Collections.emptySet());

        ServiceSchema schema = mock(ServiceSchema.class);
        when(schema.getServiceType()).thenReturn(SchemaType.USER);
        when(schema.getServiceName()).thenReturn(serviceName);
        when(schema.getVersion()).thenReturn("1.0");
        when(schema.getName()).thenReturn(serviceName);
        when(schema.getAttributeSchemas()).thenReturn(Collections.singleton(attribute));
        when(schema.getAttributeSchemaNames()).thenReturn(Collections.singleton("quota"));
        return schema;
    }

    private String getResourceId(String serviceName) {
        return serviceName.substring(0, serviceName.length() - "Service".length());
    }

    private Context createContext() {
        Context result = mock(Context.class);
        SSOTokenContext tokenContext = mock(SSOTokenContext.class);
        RealmContext realmContext = mock(RealmContext.class);
        Realm realm = mock(Realm.class);
        when(result.asContext(SSOTokenContext.class)).thenReturn(tokenContext);
        when(tokenContext.getCallerSSOToken()).thenReturn(mock(SSOToken.class));
        when(result.asContext(RealmContext.class)).thenReturn(realmContext);
        when(realmContext.getRealm()).thenReturn(realm);
        when(realm.asPath()).thenReturn("/");
        return result;
    }

}
