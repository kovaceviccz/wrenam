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

import static java.util.Collections.emptyList;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.rest.RestConstants.COLLECTION;
import static org.forgerock.openam.rest.RestConstants.NAME;
import static org.forgerock.openam.rest.RestConstants.SCHEMA;
import static org.forgerock.openam.rest.RestConstants.TEMPLATE;

import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.ServiceSchema;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.forgerock.api.models.Action;
import org.forgerock.api.models.ApiDescription;
import org.forgerock.api.models.Paths;
import org.forgerock.api.models.Resource;
import org.forgerock.api.models.VersionedPath;
import org.forgerock.http.ApiProducer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.Request;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.services.context.Context;
import org.forgerock.services.descriptor.Describable;
import org.wrensecurity.guava.common.base.Optional;

/**
 * Adapts one SMS user-service schema to the schema, template, and value shapes used by the Users REST resources.
 */
final class UserServiceSchemaProvider extends SmsResourceProvider {

    private final ApiDescription description;

    private final String resourceId;

    UserServiceSchemaProvider(ServiceSchema schema, String resourceId, Debug debug,
            AMResourceBundleCache resourceBundleCache, Locale defaultLocale, SmsJsonConverter converter) {
        super(schema, schema.getServiceType(), emptyList(), null, false, converter, debug,
                resourceBundleCache, defaultLocale);
        this.resourceId = resourceId;
        this.description = ApiDescription.apiDescription().id("user-service").version("1.0")
                .paths(Paths.paths().put("", VersionedPath.versionedPath()
                        .put(VersionedPath.UNVERSIONED, Resource.resource()
                                .title(getI18NName())
                                .description(getSchemaDescription(schema.getI18NKey()))
                                .mvccSupported(false)
                                .resourceSchema(org.forgerock.api.models.Schema.schema()
                                        .schema(createSchema(Optional.<Context>absent())).build())
                                .action(Action.action().name(SCHEMA).description(SCHEMA_DESCRIPTION).build())
                                .action(Action.action().name(TEMPLATE).description(TEMPLATE_DESCRIPTION).build())
                                .build()).build())
                        .build())
                .build();
    }

    JsonValue getSchema(Context context) {
        return createSchema(Optional.of(context));
    }

    JsonValue getTemplate() {
        return converter.toJson(schema.getAttributeDefaults(), false);
    }

    JsonValue getType() {
        return json(object(
                field(ResourceResponse.FIELD_CONTENT_ID, resourceId),
                field(NAME, getI18NName()),
                field(COLLECTION, false)));
    }

    JsonValue toJson(String realm, Map<String, Set<String>> attributes) {
        return converter.toJson(realm, canonicalizeAttributeNames(attributes), false);
    }

    Map<String, Set<String>> fromJson(String realm, JsonValue value) throws BadRequestException {
        return converter.fromJson(realm, value);
    }

    @Override
    JsonValue createSchema(Optional<Context> context) {
        JsonValue result = json(object(field("type", "object")));
        addAttributeSchema(result, "/properties/", schema, context);
        return result;
    }

    private Map<String, Set<String>> canonicalizeAttributeNames(Map<String, Set<String>> attributes) {
        Map<String, String> canonicalNames = new LinkedHashMap<>();
        for (String attributeName : (Set<String>) schema.getAttributeSchemaNames()) {
            canonicalNames.put(attributeName.toLowerCase(Locale.ROOT), attributeName);
        }

        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> entry : attributes.entrySet()) {
            String canonicalName = canonicalNames.get(entry.getKey().toLowerCase(Locale.ROOT));
            if (canonicalName != null) {
                result.put(canonicalName, entry.getValue());
            }
        }
        return result;
    }

    @Override
    public ApiDescription api(ApiProducer<ApiDescription> apiProducer) {
        return apiProducer.addApiInfo(description);
    }

    @Override
    public ApiDescription handleApiRequest(Context context, Request request) {
        return description;
    }

    @Override
    public void addDescriptorListener(Describable.Listener listener) {
    }

    @Override
    public void removeDescriptorListener(Describable.Listener listener) {
    }

}
