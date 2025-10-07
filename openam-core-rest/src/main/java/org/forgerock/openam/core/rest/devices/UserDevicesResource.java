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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025 Wren Security.
 */

package org.forgerock.openam.core.rest.devices;

import static org.forgerock.json.resource.Responses.newQueryResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.DELETE_DESCRIPTION;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.QUERY_DESCRIPTION;
import static org.forgerock.util.promise.Promises.newResultPromise;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.USER_DEVICES_RESOURCE;

import java.text.ParseException;
import java.util.List;

import org.forgerock.api.annotations.ApiError;
import org.forgerock.api.annotations.Delete;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.Query;
import org.forgerock.api.enums.QueryType;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RealmAwareResource;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * REST resource for a user's trusted devices.
 *
 * @since 13.0.0
 */
public abstract class UserDevicesResource<T extends UserDevicesDao<?>> extends RealmAwareResource {

    protected static final String UUID_KEY = "uuid";

    protected final T userDevicesDao;

    protected final ContextHelper contextHelper;

    /**
     * Constructs a new UserDevicesResource.
     *
     * @param userDevicesDao An instance of the {@code UserDevicesDao}.
     */
    public UserDevicesResource(T userDevicesDao, ContextHelper contextHelper) {
        this.userDevicesDao = userDevicesDao;
        this.contextHelper = contextHelper;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, String resourceId,
            DeleteRequest request) {

        final String userName = contextHelper.getUserId(context);

        try {
            List<JsonValue> devices = userDevicesDao.getDeviceProfiles(userName, getRealm(context));

            JsonValue toDelete = null;
            for (JsonValue device : devices) {
                if (resourceId.equals(device.get(UUID_KEY).asString())) {
                    toDelete = device;
                    break;
                }
            }

            if (toDelete == null) {
                return new NotFoundException("User device, " + resourceId + ", not found.").asPromise();
            }

            devices.remove(toDelete);

            userDevicesDao.saveDeviceProfiles(userName, getRealm(context), devices);

            return newResultPromise(newResourceResponse(resourceId, toDelete.hashCode() + "", toDelete));
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        try {
            final String userName = contextHelper.getUserId(context);

            for (JsonValue profile : userDevicesDao.getDeviceProfiles(userName, getRealm(context))) {
                handler.handleResource(convertValue(profile));
            }
            return newResultPromise(newQueryResponse());
        } catch (ParseException e) {
            return new InternalServerErrorException(e.getMessage()).asPromise();
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    protected abstract ResourceResponse convertValue(JsonValue queryResult) throws ParseException;

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context, ActionRequest actionRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, String s, ActionRequest actionRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(Context context, CreateRequest createRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, String s, PatchRequest patchRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String s, ReadRequest readRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String s, UpdateRequest updateRequest) {
        return RestUtils.generateUnsupportedOperation();
    }
}
