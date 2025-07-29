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
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.locale.AMResourceBundleCache;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.SchemaType;
import com.sun.identity.sm.ServiceSchema;
import com.sun.identity.sm.ServiceSchemaManager;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.RequestHandler;
import org.forgerock.api.annotations.Schema;
import org.forgerock.api.enums.ParameterSource;
import org.forgerock.api.models.Action;
import org.forgerock.api.models.ApiDescription;
import org.forgerock.api.models.Create;
import org.forgerock.api.models.Delete;
import org.forgerock.api.models.Parameter;
import org.forgerock.api.models.Paths;
import org.forgerock.api.models.Read;
import org.forgerock.api.models.Resource;
import org.forgerock.api.models.Update;
import org.forgerock.api.models.VersionedPath;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.identity.idm.AMIdentityRepositoryFactory;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.i18n.LocalizableString;
import org.forgerock.util.promise.Promise;
import org.wrensecurity.guava.common.base.Optional;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.forgerock.api.enums.CreateMode.ID_FROM_SERVER;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.util.promise.Promises.newResultPromise;

@RequestHandler(@Handler(mvccSupported = false, resourceSchema = @Schema(fromType = Object.class)))
public class SmsUserServiceSingletonProvider extends SmsSingletonProvider {

    private static final LocalizableString UNASSIGNED_DESCRIPTION =
            new LocalizableString("i18n:api-descriptor/SmsResourceProvider#action.unassignServices.description",
                    SmsUserServiceSingletonProvider.class.getClassLoader());

    private final ContextHelper contextHelper;

    @Inject
    SmsUserServiceSingletonProvider(
            @Assisted SmsJsonConverter converter,
            @Assisted("schema") ServiceSchema schema,
            @Assisted("dynamic") @Nullable ServiceSchema dynamicSchema,
            @Assisted SchemaType type,
            @Assisted List<ServiceSchema> subSchemaPath,
            @Assisted String uriPath,
            @Assisted boolean serviceHasInstanceName,
            @Named("frRest") Debug debug,
            @Named("AMResourceBundleCache") AMResourceBundleCache resourceBundleCache,
            @Named("DefaultLocale") Locale defaultLocale,
            AMIdentityRepositoryFactory idRepoFactory,
            ContextHelper contextHelper) {
        super(converter, schema, dynamicSchema, type, subSchemaPath, uriPath, serviceHasInstanceName,
                debug, resourceBundleCache, defaultLocale, idRepoFactory);
        this.contextHelper = contextHelper;
    }

    @Override
    protected ApiDescription initDescription(ServiceSchema schema) {
        Parameter usernameParameter = Parameter.parameter()
                .name("user")
                .type("String")
                .source(ParameterSource.PATH)
                .description("The user's username")
                .build();
        JsonValue unassignServices = json(object(
                field("type", "object"),
                field("title", "i18n:api-descriptor/UserServicesResource#schema.title"),
                field("description", "i18n:api-descriptor/UserServicesResource#schema.description"),
                field("properties", object(
                        field("serviceNames", object(
                                field("type", "array"),
                                field("title", "i18n:api-descriptor/UserServicesResource#schema.servicename.title"),
                                field("description", "i18n:api-descriptor/UserServicesResource#schema.servicename.description"),
                                field("items", object(field("type", "string")))
                        ))
                ))
        ));

        return ApiDescription.apiDescription()
                .id("fake")
                .version("v")
                .paths(Paths.paths().put("", VersionedPath.versionedPath().put(
                        VersionedPath.UNVERSIONED,
                        Resource.resource()
                                .title(getI18NName())
                                .description(getSchemaDescription(schema.getI18NKey()))
                                .mvccSupported(false)
                                .resourceSchema(org.forgerock.api.models.Schema.schema()
                                        .schema(createSchema(Optional.<Context>absent()))
                                        .build())
                                .read(Read.read().parameter(usernameParameter).build())
                                .update(Update.update().parameter(usernameParameter).build())
                                .delete(Delete.delete().parameter(usernameParameter).build())
                                .create(Create.create()
                                        .parameter(usernameParameter)
                                        .mode(ID_FROM_SERVER)
                                        .singleton(true)
                                        .build())
                                .action(Action.action().name("schema").description(SCHEMA_DESCRIPTION).build())
                                .action(Action.action().name("template").description(TEMPLATE_DESCRIPTION).build())
                                .action(Action.action()
                                        .name("unassignServices")
                                        .parameter(usernameParameter)
                                        .request(org.forgerock.api.models.Schema.schema()
                                                .schema(unassignServices).build())
                                        .description(UNASSIGNED_DESCRIPTION)
                                        .build())
                                .build()).build()
                ).build()).build();
    }

    @org.forgerock.api.annotations.Create(operationDescription = @Operation)
    @Override
    public Promise<ResourceResponse, ResourceException> handleCreate(Context serverContext, CreateRequest request) {
        try {
            String userId = contextHelper.getUserId(serverContext);
            String realm = realmFor(serverContext);
            AMIdentity amid = IdUtils.getIdentity(userId, realm);
            Map<String, Set<String>> attributes = converter.fromJson(request.getContent());
            amid.assignService(serviceName, attributes);
            Map<String, Set<String>> updatedAttributes = amid.getServiceAttributes(serviceName);
            JsonValue result = json(object());
            converter.toJson(updatedAttributes, false, result);
            return newResultPromise(newResourceResponse(serviceName, String.valueOf(result.hashCode()), result));
        } catch (IdRepoException | SSOException e) {
            debug.warning("::SmsCollectionProvider:: {} on Create", e.getClass().getSimpleName(), e);
            return new InternalServerErrorException("Unable to create SMS config: " + e.getMessage()).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @org.forgerock.api.annotations.Read(operationDescription = @Operation)
    @Override
    public Promise<ResourceResponse, ResourceException> handleRead(Context serverContext) {
        try {
            String userId = contextHelper.getUserId(serverContext);
            String realm = realmFor(serverContext);
            AMIdentity amid = IdUtils.getIdentity(userId, realm);
            Set<String> serviceNames = amid.getAssignedServices();
            if (!serviceNames.contains(serviceName)) {
                throw new NotFoundException();
            } else {
                Map<String, Set<String>> serviceAttributes = amid.getServiceAttributes(serviceName);
                JsonValue result = json(object());
                converter.toJson(serviceAttributes, false, result);
                return newResultPromise(newResourceResponse(serviceName, String.valueOf(result.hashCode()), result));
            }
        } catch (SSOException | IdRepoException e) {
            debug.warning("::SmsSingletonProvider:: {} on Read", e.getClass().getSimpleName(), e);
            return new InternalServerErrorException("Unable to read SMS config: " + e.getMessage()).asPromise();
        } catch (NotFoundException e) {
            return e.asPromise();
        }
    }

    @org.forgerock.api.annotations.Update(operationDescription = @Operation)
    @Override
    public Promise<ResourceResponse, ResourceException> handleUpdate(Context serverContext, UpdateRequest request) {
        try {
            String userId = contextHelper.getUserId(serverContext);
            String realm = realmFor(serverContext);
            AMIdentity amid = IdUtils.getIdentity(userId, realm);
            Map<String, Set<String>> newValues = converter.fromJson(request.getContent());
            amid.modifyService(serviceName, newValues);
            Map<String, Set<String>> updatedAttributes = amid.getServiceAttributes(serviceName);
            JsonValue result = json(object());
            converter.toJson(updatedAttributes, false, result);
            return newResultPromise(newResourceResponse(serviceName, String.valueOf(result.hashCode()), result));
        } catch (IdRepoException | SSOException e) {
            debug.warning("::SmsCollectionProvider:: SSOException on update", e);
            return new InternalServerErrorException("Unable to update SMS config: " + e.getMessage()).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @org.forgerock.api.annotations.Delete(operationDescription = @Operation)
    @Override
    public Promise<ResourceResponse, ResourceException> handleDelete(Context ctx) {
        return new NotSupportedException("Not supported, please use 'unassignServices' action instead").asPromise();
    }

    @org.forgerock.api.annotations.Action(name = "unassignServices",
            operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> unassignServices(Context serverContext, ActionRequest request) {

        try {
            String userId = contextHelper.getUserId(serverContext);
            String realm = realmFor(serverContext);
            AMIdentity amid = IdUtils.getIdentity(userId, realm);
            if (amid == null) {
                throw new BadRequestException("Unknown user " + userId);
            }

            JsonValue requestedServicesToRemove = request.getContent().get("serviceNames");
            if (requestedServicesToRemove == null) {
                throw new BadRequestException("Missing 'serviceNames' attribute");
            }

            Map<String, String> resourceNameToServiceName = new HashMap<>();

            for (String assignedService : amid.getAssignedServices()) {
                ServiceSchemaManager ssm = new ServiceSchemaManager(assignedService,
                        serverContext.asContext(SSOTokenContext.class).getCallerSSOToken());
                resourceNameToServiceName.put(ssm.getResourceName(), ssm.getSchema(SchemaType.USER).getServiceName());
            }

            Set<String> assignedServices = amid.getAssignedServices();
            List<String> servicesToBeRemoved = new ArrayList<>();

            for (String resourceName : requestedServicesToRemove.asCollection(String.class)) {
                String serviceName = resourceNameToServiceName.get(resourceName);
                if (assignedServices.contains(serviceName)) {
                    servicesToBeRemoved.add(serviceName);
                }
            }

            for (String serviceName : servicesToBeRemoved) {
                amid.unassignService(serviceName);
            }
        } catch (SSOException | IdRepoException | SMSException e) {
            debug.warning("SmsSingletonProvider: {} on unassignServices", e.getClass().getSimpleName(), e);
            return new InternalServerErrorException("Unable to modify user services: " + e.getMessage()).asPromise();
        } catch (BadRequestException e) {
            return e.asPromise();
        }

        return newResultPromise(newActionResponse(json(object())));
    }
}
