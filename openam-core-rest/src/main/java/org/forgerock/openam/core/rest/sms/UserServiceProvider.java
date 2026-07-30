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

import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newResourceResponse;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoErrorCode;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.AttributeSchema;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceNotFoundException;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.forgerock.json.JsonException;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ConflictException;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.PermanentException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;

/**
 * Resolves and modifies the SMS services that are assigned or assignable to one AM user.
 *
 * Service types are resolved from the selected user's authoritative assigned and assignable sets. The provider maps
 * internal SMS service names to their public resource IDs and rejects duplicate resource IDs before an operation can
 * address the wrong service.
 */
@Singleton
final class UserServiceProvider {

    private static final String AUTH_CONFIGURATION_SERVICE = "iPlanetAMAuthConfiguration";

    private static final String RESULT = "result";

    private static final String SAML_SERVICE = "iPlanetAMSAMLService";

    private static final String USER_SERVICE = "iPlanetAMUserService";

    private final Debug debug;

    private final AMResourceBundleCache resourceBundleCache;

    private final Locale defaultLocale;

    private final SmsConsoleServiceNameFilter consoleServiceNameFilter;

    @Inject
    UserServiceProvider(@Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale,
            SmsConsoleServiceNameFilter consoleServiceNameFilter) {
        this.debug = debug;
        this.resourceBundleCache = resourceBundleCache;
        this.defaultLocale = defaultLocale;
        this.consoleServiceNameFilter = consoleServiceNameFilter;
    }

    JsonValue getAllTypes(Context context, String userId) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        Map<String, ServiceSchema> schemas = getAssignedSchemas(context, user);
        mergeSchemas(schemas, getAssignableSchemas(context, user));
        return buildTypeResponse(schemas);
    }

    JsonValue getCreatableTypes(Context context, String userId) throws ResourceException {
        return buildTypeResponse(getAssignableSchemas(context, getUser(context, userId)));
    }

    JsonValue getAssignedInstances(Context context, String userId) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        JsonValue response = json(object(field(RESULT, array())));
        for (Map.Entry<String, ServiceSchema> entry : getAssignedSchemas(context, user).entrySet()) {
            response.get(RESULT).add(readContent(context, user, entry.getKey(), entry.getValue()).getObject());
        }
        return response;
    }

    JsonValue getSchema(Context context, String userId, String resourceId) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        ServiceSchema schema = getAvailableSchema(context, user, resourceId);
        return createSchemaProvider(schema, resourceId).getSchema(context);
    }

    JsonValue getTemplate(Context context, String userId, String resourceId) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        ServiceSchema schema = getAvailableSchema(context, user, resourceId);
        return createSchemaProvider(schema, resourceId).getTemplate();
    }

    ResourceResponse read(Context context, String userId, String resourceId) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        ServiceSchema schema = getRequiredSchema(getAssignedSchemas(context, user), resourceId);
        JsonValue content = readContent(context, user, resourceId, schema);
        return newResourceResponse(resourceId, String.valueOf(content.hashCode()), content);
    }

    ResourceResponse create(Context context, String userId, String resourceId, JsonValue content)
            throws ResourceException {
        AMIdentity user = getUser(context, userId);
        if (getAssignedSchemas(context, user).containsKey(resourceId)) {
            throw new ConflictException("Service is already assigned to the user");
        }

        ServiceSchema schema = getRequiredSchema(getAssignableSchemas(context, user), resourceId);
        Map<String, Set<String>> attributes = fromJson(context, schema, resourceId, content);
        try {
            user.assignService(schema.getServiceName(), attributes);
        } catch (IdRepoException e) {
            String errorCode = e.getErrorCode();
            if (IdRepoErrorCode.SERVICE_ALREADY_ASSIGNED.equals(errorCode)) {
                throw new ConflictException("Unable to assign user service");
            }
            if (IdRepoErrorCode.SERVICE_NOT_ASSIGNED.equals(errorCode)
                    || IdRepoErrorCode.UNABLE_GET_SERVICE_SCHEMA.equals(errorCode)
                    || IdRepoErrorCode.TYPE_NOT_FOUND.equals(errorCode)) {
                throw new NotFoundException("Unable to assign user service");
            }
            if (IdRepoErrorCode.DATA_INVALID_FOR_SERVICE.equals(errorCode)
                    || IdRepoErrorCode.ILLEGAL_ARGUMENTS.equals(errorCode)
                    || IdRepoErrorCode.IDENTITY_ATTRIBUTE_INVALID.equals(errorCode)) {
                throw new BadRequestException("Unable to assign user service");
            }
            if (IdRepoErrorCode.ACCESS_DENIED.equals(errorCode)) {
                throw new ForbiddenException("Unable to assign user service");
            }
            debug.warning("Unable to assign user service", e);
            throw new InternalServerErrorException("Unable to assign user service");
        } catch (SSOException e) {
            debug.warning("Unable to assign user service: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        }

        JsonValue result = readContent(context, user, resourceId, schema);
        return newResourceResponse(resourceId, String.valueOf(result.hashCode()), result);
    }

    ResourceResponse update(Context context, String userId, String resourceId, JsonValue content)
            throws ResourceException {
        AMIdentity user = getUser(context, userId);
        ServiceSchema schema = getRequiredSchema(getAssignedSchemas(context, user), resourceId);
        Map<String, Set<String>> attributes = fromJson(context, schema, resourceId, content);
        try {
            user.modifyService(schema.getServiceName(), attributes);
        } catch (IdRepoException e) {
            String errorCode = e.getErrorCode();
            if (IdRepoErrorCode.SERVICE_NOT_ASSIGNED.equals(errorCode)
                    || IdRepoErrorCode.UNABLE_GET_SERVICE_SCHEMA.equals(errorCode)
                    || IdRepoErrorCode.TYPE_NOT_FOUND.equals(errorCode)) {
                throw new NotFoundException("Unable to update user service");
            }
            if (IdRepoErrorCode.DATA_INVALID_FOR_SERVICE.equals(errorCode)
                    || IdRepoErrorCode.ILLEGAL_ARGUMENTS.equals(errorCode)
                    || IdRepoErrorCode.IDENTITY_ATTRIBUTE_INVALID.equals(errorCode)) {
                throw new BadRequestException("Unable to update user service");
            }
            if (IdRepoErrorCode.ACCESS_DENIED.equals(errorCode)) {
                throw new ForbiddenException("Unable to update user service");
            }
            debug.warning("Unable to update user service", e);
            throw new InternalServerErrorException("Unable to update user service");
        } catch (SSOException e) {
            debug.warning("Unable to update user service: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        }

        JsonValue result = readContent(context, user, resourceId, schema);
        return newResourceResponse(resourceId, String.valueOf(result.hashCode()), result);
    }

    JsonValue unassign(Context context, String userId, Collection<String> resourceIds) throws ResourceException {
        AMIdentity user = getUser(context, userId);
        Map<String, ServiceSchema> assignedSchemas = getAssignedSchemas(context, user);
        Set<ServiceSchema> requestedSchemas = new LinkedHashSet<>();
        for (String resourceId : resourceIds) {
            ServiceSchema schema = assignedSchemas.get(resourceId);
            if (schema == null) {
                throw new NotFoundException("Service is not assigned to the user: " + resourceId);
            }
            requestedSchemas.add(schema);
        }

        for (ServiceSchema schema : requestedSchemas) {
            try {
                user.unassignService(schema.getServiceName());
            } catch (IdRepoException e) {
                String errorCode = e.getErrorCode();
                if (IdRepoErrorCode.SERVICE_NOT_ASSIGNED.equals(errorCode)
                        || IdRepoErrorCode.UNABLE_GET_SERVICE_SCHEMA.equals(errorCode)
                        || IdRepoErrorCode.TYPE_NOT_FOUND.equals(errorCode)) {
                    throw new NotFoundException("Unable to unassign user service");
                }
                if (IdRepoErrorCode.ACCESS_DENIED.equals(errorCode)) {
                    throw new ForbiddenException("Unable to unassign user service");
                }
                debug.warning("Unable to unassign user service", e);
                throw new InternalServerErrorException("Unable to unassign user service");
            } catch (SSOException e) {
                debug.warning("Unable to unassign user service: unauthorized", e);
                throw new PermanentException(401, "Unauthorized", null);
            }
        }
        return json(object(field("success", true)));
    }

    private JsonValue buildTypeResponse(Map<String, ServiceSchema> schemas) {
        JsonValue response = json(object(field(RESULT, array())));
        for (Map.Entry<String, ServiceSchema> entry : schemas.entrySet()) {
            response.get(RESULT).add(createSchemaProvider(entry.getValue(), entry.getKey()).getType().getObject());
        }
        return response;
    }

    private ServiceSchema getAvailableSchema(Context context, AMIdentity user, String resourceId)
            throws ResourceException {
        Map<String, ServiceSchema> schemas = getAssignedSchemas(context, user);
        mergeSchemas(schemas, getAssignableSchemas(context, user));
        return getRequiredSchema(schemas, resourceId);
    }

    private ServiceSchema getRequiredSchema(Map<String, ServiceSchema> schemas, String resourceId)
            throws NotFoundException {
        ServiceSchema schema = schemas.get(resourceId);
        if (schema == null) {
            throw new NotFoundException("User service not found: " + resourceId);
        }
        return schema;
    }

    private Map<String, ServiceSchema> getAssignedSchemas(Context context, AMIdentity user) throws ResourceException {
        return getServiceSchemas(context, getAssignedServices(user));
    }

    private Map<String, ServiceSchema> getAssignableSchemas(Context context, AMIdentity user) throws ResourceException {
        return getServiceSchemas(context, getAssignableServices(user));
    }

    private Map<String, ServiceSchema> getServiceSchemas(Context context, Set<String> serviceNames)
            throws ResourceException {
        SSOToken token = context.asContext(SSOTokenContext.class).getCallerSSOToken();
        Map<String, ServiceSchema> result = new LinkedHashMap<>();
        for (String serviceName : new TreeSet<>(serviceNames)) {
            try {
                ServiceSchemaManager schemaManager = new ServiceSchemaManager(serviceName, token);
                ServiceSchema schema = schemaManager.getUserSchema();
                String resourceId = schemaManager.getResourceName();
                if (schema == null || StringUtils.isEmpty(resourceId) || !hasDisplayableAttribute(schema)) {
                    continue;
                }

                ServiceSchema previous = result.put(resourceId, schema);
                if (previous != null && !previous.getServiceName().equals(schema.getServiceName())) {
                    throw new InternalServerErrorException(
                            "Multiple user services use resource ID: " + resourceId);
                }
            } catch (ServiceNotFoundException e) {
                debug.warning("User service schema no longer exists: {}", serviceName, e);
            } catch (SMSException | SSOException e) {
                debug.warning("Unable to read schema for user service {}", serviceName, e);
                throw new InternalServerErrorException(
                        "Unable to read schema for user service " + serviceName);
            }
        }
        return result;
    }

    private boolean hasDisplayableAttribute(ServiceSchema schema) {
        for (AttributeSchema attribute : (Set<AttributeSchema>) schema.getAttributeSchemas()) {
            if (!StringUtils.isBlank(attribute.getI18NKey())) {
                return true;
            }
        }
        return false;
    }

    private void mergeSchemas(Map<String, ServiceSchema> target, Map<String, ServiceSchema> source)
            throws InternalServerErrorException {
        for (Map.Entry<String, ServiceSchema> entry : source.entrySet()) {
            ServiceSchema previous = target.put(entry.getKey(), entry.getValue());
            if (previous != null && !previous.getServiceName().equals(entry.getValue().getServiceName())) {
                throw new InternalServerErrorException(
                        "Multiple user services use resource ID: " + entry.getKey());
            }
        }
    }

    private Set<String> getAssignedServices(AMIdentity user) throws ResourceException {
        try {
            Set<String> services = new HashSet<>(user.getAssignedServices());
            filterServices(services);
            return services;
        } catch (IdRepoException e) {
            if (IdRepoErrorCode.ACCESS_DENIED.equals(e.getErrorCode())) {
                throw new ForbiddenException("Unable to read assigned user services");
            }
            debug.warning("Unable to read assigned user services", e);
            throw new InternalServerErrorException("Unable to read assigned user services");
        } catch (SSOException e) {
            debug.warning("Unable to read assigned user services: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        } catch (SMSException e) {
            debug.warning("Unable to filter assigned user services", e);
            throw new InternalServerErrorException("Unable to filter assigned user services");
        }
    }

    private Set<String> getAssignableServices(AMIdentity user) throws ResourceException {
        try {
            Set<String> services = new HashSet<>(user.getAssignableServices());
            filterServices(services);
            services.remove(SAML_SERVICE);
            return services;
        } catch (IdRepoException e) {
            if (IdRepoErrorCode.ACCESS_DENIED.equals(e.getErrorCode())) {
                throw new ForbiddenException("Unable to read assignable user services");
            }
            debug.warning("Unable to read assignable user services", e);
            throw new InternalServerErrorException("Unable to read assignable user services");
        } catch (SSOException e) {
            debug.warning("Unable to read assignable user services: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        } catch (SMSException e) {
            debug.warning("Unable to filter assignable user services", e);
            throw new InternalServerErrorException("Unable to filter assignable user services");
        }
    }

    private void filterServices(Set<String> services) throws SSOException, SMSException {
        consoleServiceNameFilter.filter(services);
        services.remove(USER_SERVICE);
        services.remove(AUTH_CONFIGURATION_SERVICE);
    }

    private JsonValue readContent(Context context, AMIdentity user, String resourceId, ServiceSchema schema)
            throws ResourceException {
        try {
            Map<String, Set<String>> attributes = user.getServiceAttributes(schema.getServiceName());
            UserServiceSchemaProvider provider = createSchemaProvider(schema, resourceId);
            JsonValue content = provider.toJson(
                    context.asContext(RealmContext.class).getRealm().asPath(), attributes);
            content.put(ResourceResponse.FIELD_CONTENT_ID, resourceId);
            content.put("_type", provider.getType().getObject());
            return content;
        } catch (IdRepoException e) {
            String errorCode = e.getErrorCode();
            if (IdRepoErrorCode.SERVICE_NOT_ASSIGNED.equals(errorCode)
                    || IdRepoErrorCode.UNABLE_GET_SERVICE_SCHEMA.equals(errorCode)
                    || IdRepoErrorCode.TYPE_NOT_FOUND.equals(errorCode)) {
                throw new NotFoundException("Unable to read user service");
            }
            if (IdRepoErrorCode.ACCESS_DENIED.equals(errorCode)) {
                throw new ForbiddenException("Unable to read user service");
            }
            debug.warning("Unable to read user service", e);
            throw new InternalServerErrorException("Unable to read user service");
        } catch (SSOException e) {
            debug.warning("Unable to read user service: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        } catch (JsonException e) {
            debug.warning("Unable to convert user service", e);
            throw new InternalServerErrorException("Unable to convert user service");
        }
    }

    private Map<String, Set<String>> fromJson(Context context, ServiceSchema schema, String resourceId,
            JsonValue content) throws ResourceException {
        try {
            return createSchemaProvider(schema, resourceId)
                    .fromJson(context.asContext(RealmContext.class).getRealm().asPath(), content);
        } catch (BadRequestException e) {
            throw e;
        } catch (JsonException e) {
            throw new BadRequestException("Invalid user service attributes");
        }
    }

    private AMIdentity getUser(Context context, String userId) throws ResourceException {
        SSOToken token = context.asContext(SSOTokenContext.class).getCallerSSOToken();
        String realm = context.asContext(RealmContext.class).getRealm().asPath();
        try {
            AMIdentity user = new AMIdentity(token, userId, IdType.USER, realm, null);
            if (!user.isExists()) {
                throw new NotFoundException("User not found: " + userId);
            }
            return user;
        } catch (IdRepoException e) {
            String errorCode = e.getErrorCode();
            if (IdRepoErrorCode.TYPE_NOT_FOUND.equals(errorCode)) {
                throw new NotFoundException("Unable to read user for user service");
            }
            if (IdRepoErrorCode.ILLEGAL_ARGUMENTS.equals(errorCode)
                    || IdRepoErrorCode.IDENTITY_ATTRIBUTE_INVALID.equals(errorCode)) {
                throw new BadRequestException("Unable to read user for user service");
            }
            if (IdRepoErrorCode.ACCESS_DENIED.equals(errorCode)) {
                throw new ForbiddenException("Unable to read user for user service");
            }
            debug.warning("Unable to read user for user service", e);
            throw new InternalServerErrorException("Unable to read user for user service");
        } catch (SSOException e) {
            debug.warning("Unable to read user for user service: unauthorized", e);
            throw new PermanentException(401, "Unauthorized", null);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid user identifier");
        }
    }

    private UserServiceSchemaProvider createSchemaProvider(ServiceSchema schema, String resourceId) {
        return new UserServiceSchemaProvider(schema, resourceId, debug, resourceBundleCache, defaultLocale,
                new SmsJsonConverter(schema));
    }

}
