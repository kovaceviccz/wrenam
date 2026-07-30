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

import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.openam.rest.RestConstants.SCHEMA;
import static org.forgerock.openam.rest.RestConstants.TEMPLATE;

import jakarta.inject.Inject;
import java.util.Map;
import org.forgerock.api.annotations.Action;
import org.forgerock.api.annotations.Create;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.Read;
import org.forgerock.api.annotations.RequestHandler;
import org.forgerock.api.annotations.Schema;
import org.forgerock.api.annotations.Update;
import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Exposes schema, template, and value operations for one service of one AM user.
 */
@RequestHandler(@Handler(mvccSupported = false, resourceSchema = @Schema(fromType = Object.class)))
public final class UserServiceResource {

    private static final String SERVICE = "service";

    private final ContextHelper contextHelper;

    private final UserServiceProvider userServices;

    @Inject
    public UserServiceResource(ContextHelper contextHelper, UserServiceProvider userServices) {
        this.contextHelper = contextHelper;
        this.userServices = userServices;
    }

    @Action(name = SCHEMA, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> getSchema(Context context, ActionRequest request) {
        try {
            return newActionResponse(userServices.getSchema(
                    context, contextHelper.getUserId(context), getServiceId(context))).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Action(name = TEMPLATE, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> getTemplate(Context context, ActionRequest request) {
        try {
            return newActionResponse(userServices.getTemplate(
                    context, contextHelper.getUserId(context), getServiceId(context))).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Read(operationDescription = @Operation)
    public Promise<ResourceResponse, ResourceException> read(Context context) {
        try {
            return userServices.read(context, contextHelper.getUserId(context), getServiceId(context)).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Create(operationDescription = @Operation)
    public Promise<ResourceResponse, ResourceException> create(Context context, CreateRequest request) {
        try {
            return userServices.create(context, contextHelper.getUserId(context), getServiceId(context),
                    request.getContent()).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Update(operationDescription = @Operation)
    public Promise<ResourceResponse, ResourceException> update(Context context, UpdateRequest request) {
        try {
            return userServices.update(context, contextHelper.getUserId(context), getServiceId(context),
                    request.getContent()).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    private String getServiceId(Context context) {
        UriRouterContext routerContext = context.asContext(UriRouterContext.class);
        Map<String, String> variables = routerContext.getUriTemplateVariables();
        String serviceId = variables.get(SERVICE);
        if (serviceId == null && !routerContext.isRootContext()
                && routerContext.getParent().containsContext(UriRouterContext.class)) {
            return getServiceId(routerContext.getParent());
        }
        return serviceId;
    }

}
