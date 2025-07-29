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
 * Copyright 2025 Wren Security
 */
package org.forgerock.openam.core.rest.sms;

import com.google.inject.assistedinject.Assisted;
import java.util.List;
import javax.annotation.Nullable;

import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;

public interface SmsUserServiceSingletonProviderFactory {

    SmsUserServiceSingletonProvider create(
            @Assisted SmsJsonConverter converter,
            @Assisted("schema")  ServiceSchema schema,
            @Assisted("dynamic") @Nullable ServiceSchema dynamicSchema,
            @Assisted SchemaType type,
            @Assisted List<ServiceSchema> subSchemaPath,
            @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName);
}
