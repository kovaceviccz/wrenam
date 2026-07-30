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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;
import java.util.Collections;
import java.util.Locale;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class UserServiceSchemaProviderTest {

    private UserServiceSchemaProvider provider;

    @BeforeMethod
    public void setUp() {
        AttributeSchema attribute = mock(AttributeSchema.class);
        ServiceSchema schema = mock(ServiceSchema.class);
        when(schema.getServiceType()).thenReturn(SchemaType.USER);
        when(schema.getServiceName()).thenReturn("iPlanetAMSessionService");
        when(schema.getVersion()).thenReturn("1.0");
        when(schema.getName()).thenReturn("iPlanetAMSessionService");
        when(schema.getI18NFileName()).thenReturn("amSession");
        when(schema.getI18NKey()).thenReturn("iplanet-am-session-service-description");
        when(schema.getAttributeSchemaNames()).thenReturn(Collections.singleton("iplanet-am-session-quota-limit"));
        when(schema.getAttributeSchemas()).thenReturn(Collections.singleton(attribute));
        when(attribute.getName()).thenReturn("iplanet-am-session-quota-limit");
        when(attribute.getResourceName()).thenReturn("quotaLimit");
        when(attribute.getI18NKey()).thenReturn("a118");
        when(attribute.getType()).thenReturn(AttributeSchema.Type.SINGLE);
        when(attribute.getSyntax()).thenReturn(AttributeSchema.Syntax.NUMBER);
        when(attribute.isOptional()).thenReturn(true);
        when(attribute.getExampleValues()).thenReturn(Collections.emptySet());

        provider = new UserServiceSchemaProvider(schema, "session", mock(Debug.class),
                mock(AMResourceBundleCache.class), Locale.ENGLISH, new SmsJsonConverter(schema));
    }

    @Test
    public void shouldExposeUserAttributesThroughTheSharedSmsSchemaConverter() {
        JsonValue schema = provider.getSchema(mock(Context.class));

        assertThat(schema.get("properties").get("quotaLimit").get("type").asString()).isEqualTo("integer");
    }

    @Test
    public void shouldUseSmsResourceNameAsStableTypeId() {
        JsonValue type = provider.getType();

        assertThat(type.get("_id").asString()).isEqualTo("session");
        assertThat(type.get("collection").asBoolean()).isFalse();
    }

}
