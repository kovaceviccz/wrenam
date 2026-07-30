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
import static org.forgerock.openam.rest.RestConstants.GET_ALL_TYPES;
import static org.forgerock.openam.rest.RestConstants.GET_CREATABLE_TYPES;
import static org.forgerock.openam.rest.RestConstants.NEXT_DESCENDENTS;

import jakarta.inject.Inject;
import java.util.List;
import org.forgerock.api.annotations.Action;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.RequestHandler;
import org.forgerock.api.annotations.Schema;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Exposes collection actions for the services assigned or assignable to one AM user.
 */
@RequestHandler(@Handler(mvccSupported = false, resourceSchema = @Schema(fromType = Object.class)))
public final class UserServicesResource {

    private static final String SERVICE_NAMES = "serviceNames";

    private static final String UNASSIGN_SERVICES = "unassignServices";

    private final ContextHelper contextHelper;

    private final UserServiceProvider userServices;

    @Inject
    public UserServicesResource(ContextHelper contextHelper, UserServiceProvider userServices) {
        this.contextHelper = contextHelper;
        this.userServices = userServices;
    }

    @Action(name = GET_ALL_TYPES, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> getAllTypes(Context context, ActionRequest request) {
        try {
            return newActionResponse(userServices.getAllTypes(context, contextHelper.getUserId(context))).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Action(name = NEXT_DESCENDENTS, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> getNextDescendents(Context context, ActionRequest request) {
        try {
            return newActionResponse(
                    userServices.getAssignedInstances(context, contextHelper.getUserId(context))).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Action(name = GET_CREATABLE_TYPES, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> getCreatableTypes(Context context, ActionRequest request) {
        try {
            return newActionResponse(
                    userServices.getCreatableTypes(context, contextHelper.getUserId(context))).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Action(name = UNASSIGN_SERVICES, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> unassignServices(Context context, ActionRequest request) {
        JsonValue serviceNames = request.getContent().get(SERVICE_NAMES);
        if (!serviceNames.isList()) {
            return new BadRequestException(
                    "The \"" + SERVICE_NAMES + "\" field must be a JSON array of service IDs").asPromise();
        }

        final List<String> resourceIds;
        try {
            resourceIds = serviceNames.asList(String.class);
        } catch (JsonValueException e) {
            return new BadRequestException(
                    "The \"" + SERVICE_NAMES + "\" field must contain only service IDs").asPromise();
        }

        try {
            return newActionResponse(userServices.unassign(
                    context, contextHelper.getUserId(context), resourceIds)).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

}
