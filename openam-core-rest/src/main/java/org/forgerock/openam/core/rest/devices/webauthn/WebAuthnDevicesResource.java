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
 * Copyright 2025 Wren Security. All rights reserved.
 */
package org.forgerock.openam.core.rest.devices.webauthn;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.DELETE_DESCRIPTION;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.DESCRIPTION;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.PATH_PARAM;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.QUERY_DESCRIPTION;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.TITLE;
import static org.forgerock.openam.i18n.apidescriptor.ApiDescriptorConstants.WEBAUTHN_DEVICES_RESOURCE;

import jakarta.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.forgerock.api.annotations.Action;
import org.forgerock.api.annotations.ApiError;
import org.forgerock.api.annotations.CollectionProvider;
import org.forgerock.api.annotations.Delete;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.Parameter;
import org.forgerock.api.annotations.Query;
import org.forgerock.api.annotations.Schema;
import org.forgerock.api.enums.QueryType;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.core.rest.devices.DeviceJsonUtils;
import org.forgerock.openam.core.rest.devices.UserDevicesResource;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.utils.Alphabet;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

/**
 * A user devices resource for WebAuthn authentication devices.
 */
@CollectionProvider(
        details = @Handler(
            title = WEBAUTHN_DEVICES_RESOURCE + TITLE,
            description = WEBAUTHN_DEVICES_RESOURCE + DESCRIPTION,
            mvccSupported = true,
            parameters = {
                @Parameter(
                    name = "user",
                    type = "string",
                    description = WEBAUTHN_DEVICES_RESOURCE + "pathparams.user"
                )
            },
            resourceSchema = @Schema(schemaResource = "WebAuthnDevicesResource.schema.json")
        ),
        pathParam = @Parameter(
            name = "uuid",
            type = "string",
            description = WEBAUTHN_DEVICES_RESOURCE + PATH_PARAM + DESCRIPTION
        )
    )
public class WebAuthnDevicesResource extends UserDevicesResource<WebAuthnDevicesDao> {

    private static final String DEVICE_NAME_KEY = "deviceName";

    private static final String TYPE_KEY = "type";

    private static final String TRANSPORTS_KEY = "transports";

    private static final String CREATED_AT_KEY = "createdAt";

    private static final String RECOVERY_CODES_KEY = "recoveryCodes";

    private static final String RECOVERY_CODES_REMAINING_KEY = "recoveryCodesRemaining";

    private static final String RECOVERY_CODES_SEALED_KEY = "recoveryCodesSealed";

    private static final String WEBAUTHN_TYPE = "webAuthn";

    private static final String SIGNAL_AVAILABLE_KEY = "signalAvailable";

    private static final String RP_ID_KEY = "rpId";

    private static final String USER_ID_KEY = "userId";

    private static final String ALL_ACCEPTED_CREDENTIAL_IDS_KEY = "allAcceptedCredentialIds";

    /**
     * Action that invalidates the existing recovery codes, generates a fresh set, and returns the new
     * codes in plaintext exactly once (in the action response). Subsequent reads of a sealed device only
     * disclose the remaining count.
     */
    static final String REGENERATE_RECOVERY_CODES_ACTION = "regenerateRecoveryCodes";

    /**
     * Action that prepares a WebAuthn {@code PublicKeyCredential.signalAllAcceptedCredentials()} payload.
     */
    static final String SIGNAL_ALL_ACCEPTED_CREDENTIALS_ACTION = "signalAllAcceptedCredentials";

    private static final int NUM_RECOVERY_CODES = 10;

    private final RecoveryCodeGenerator recoveryCodeGenerator;

    private final DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils;

    /**
     * Construct a new UserDevicesResource.
     *
     * @param webAuthnDevicesDao an instance of the {@code WebAuthnDevicesDao}
     * @param contextHelper an instance of the {@code ContextHelper}
     * @param recoveryCodeGenerator generator used to mint fresh recovery codes on regeneration
     * @param jsonUtils utility used to parse stored WebAuthn credential records
     */
    @Inject
    public WebAuthnDevicesResource(WebAuthnDevicesDao webAuthnDevicesDao, ContextHelper contextHelper,
            RecoveryCodeGenerator recoveryCodeGenerator, DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils) {
        super(webAuthnDevicesDao, contextHelper);
        this.recoveryCodeGenerator = recoveryCodeGenerator;
        this.jsonUtils = jsonUtils;
    }

    @Override
    protected ResourceResponse convertValue(JsonValue profile) {
        String deviceName = profile.get(DEVICE_NAME_KEY).asString();
        boolean sealed = profile.get(RECOVERY_CODES_SEALED_KEY).defaultTo(Boolean.FALSE).asBoolean();
        int remaining = profile.get(RECOVERY_CODES_KEY).isList() ? profile.get(RECOVERY_CODES_KEY).size() : 0;
        // Expose management data, but never credential material via the devices endpoint
        JsonValue response = json(object(
                field(UUID_KEY, profile.get(UUID_KEY).asString()),
                field(DEVICE_NAME_KEY, deviceName),
                field(TYPE_KEY, WEBAUTHN_TYPE)));
        if (profile.get(TRANSPORTS_KEY).isList()) {
            response.put(TRANSPORTS_KEY, profile.get(TRANSPORTS_KEY).copy());
        }
        putIfDefined(response, profile, CREATED_AT_KEY);
        // Recovery codes are a bearer credential. Their plaintext is only ever returned while the device is
        // unsealed (OATH/Push, which never seal). Once sealed (WebAuthn, after its one-time reveal at
        // registration or regeneration) we disclose only the remaining count, never the values themselves.
        response.put(RECOVERY_CODES_SEALED_KEY, sealed);
        response.put(RECOVERY_CODES_REMAINING_KEY, remaining);
        if (!sealed && profile.get(RECOVERY_CODES_KEY).isList()) {
            response.put(RECOVERY_CODES_KEY, profile.get(RECOVERY_CODES_KEY).copy());
        }
        return newResourceResponse(response.get(UUID_KEY).asString(), Integer.toString(response.hashCode()), response);
    }

    @Override
    @Delete(operationDescription = @Operation(
            errors = {
                    @ApiError(
                            code = 500,
                            description = WEBAUTHN_DEVICES_RESOURCE + "error.unexpected.server.error.description")},
            description = WEBAUTHN_DEVICES_RESOURCE + DELETE_DESCRIPTION))
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, String resourceId,
            DeleteRequest request) {
        try {
            final String userName = contextHelper.getUserId(context);
            List<JsonValue> devices = userDevicesDao.getDeviceProfiles(userName, getRealm(context));
            JsonValue device = findDevice(devices, resourceId);
            if (device == null) {
                return new NotFoundException("User WebAuthn device, " + resourceId + ", not found.").asPromise();
            }

            devices.remove(device);
            userDevicesDao.saveDeviceProfiles(userName, getRealm(context), devices);
            return Promises.newResultPromise(convertValue(device));
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    @Override
    @Action(name = SIGNAL_ALL_ACCEPTED_CREDENTIALS_ACTION,
            operationDescription = @Operation(
                errors = {
                        @ApiError(
                                code = 500,
                                description = WEBAUTHN_DEVICES_RESOURCE + "error.unexpected.server.error.description")},
                description = WEBAUTHN_DEVICES_RESOURCE + "action.signalAllAcceptedCredentials." + DESCRIPTION),
            request = @Schema(),
            response = @Schema(schemaResource =
                    "WebAuthnDevicesResource.action.signalAllAcceptedCredentials.response.schema.json"))
    public Promise<ActionResponse, ResourceException> actionCollection(Context context, ActionRequest request) {
        if (!SIGNAL_ALL_ACCEPTED_CREDENTIALS_ACTION.equals(request.getAction())) {
            return new NotSupportedException("Unsupported action: " + request.getAction()).asPromise();
        }
        try {
            final String userName = contextHelper.getUserId(context);
            List<JsonValue> devices = userDevicesDao.getDeviceProfiles(userName, getRealm(context));
            return Promises.newResultPromise(newActionResponse(signalAllAcceptedCredentialsPayload(devices)));
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        } catch (IOException e) {
            return new InternalServerErrorException("Failed preparing accepted WebAuthn credential signal.", e)
                    .asPromise();
        }
    }

    @Override
    @Action(name = REGENERATE_RECOVERY_CODES_ACTION,
            operationDescription = @Operation(
                errors = {
                        @ApiError(
                                code = 500,
                                description = WEBAUTHN_DEVICES_RESOURCE + "error.unexpected.server.error.description")},
                description = WEBAUTHN_DEVICES_RESOURCE + "action.regenerateRecoveryCodes." + DESCRIPTION))
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, String resourceId,
            ActionRequest request) {
        if (!REGENERATE_RECOVERY_CODES_ACTION.equals(request.getAction())) {
            return new NotSupportedException("Unsupported action: " + request.getAction()).asPromise();
        }
        try {
            final String userName = contextHelper.getUserId(context);
            List<JsonValue> devices = userDevicesDao.getDeviceProfiles(userName, getRealm(context));
            JsonValue device = findDevice(devices, resourceId);
            if (device == null) {
                return new NotFoundException("User WebAuthn device, " + resourceId + ", not found.").asPromise();
            }

            String[] codes = recoveryCodeGenerator.generateCodes(NUM_RECOVERY_CODES, Alphabet.ALPHANUMERIC, false);
            // Replace the codes in place; the sealed state is intentionally preserved so that WebAuthn devices
            // stay sealed and this disclosure is one-time, while OATH/Push (never sealed) keep their behaviour.
            device.put(RECOVERY_CODES_KEY, Arrays.asList(codes));
            userDevicesDao.saveDeviceProfiles(userName, getRealm(context), devices);

            boolean sealed = device.get(RECOVERY_CODES_SEALED_KEY).defaultTo(Boolean.FALSE).asBoolean();
            JsonValue result = json(object(
                    field(RECOVERY_CODES_KEY, Arrays.asList(codes)),
                    field(RECOVERY_CODES_REMAINING_KEY, codes.length),
                    field(RECOVERY_CODES_SEALED_KEY, sealed)));
            return Promises.newResultPromise(newActionResponse(result));
        } catch (CodeException e) {
            return new InternalServerErrorException("Failed generating recovery codes.", e).asPromise();
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    private JsonValue signalAllAcceptedCredentialsPayload(List<JsonValue> devices) throws IOException {
        List<WebAuthnDeviceSettings> credentialRecords = jsonUtils.toDeviceSettingValues(devices);
        if (credentialRecords.isEmpty()) {
            return signalUnavailable();
        }

        String rpId = null;
        String userId = null;
        List<String> acceptedCredentialIds = new ArrayList<>(credentialRecords.size());
        for (WebAuthnDeviceSettings device : credentialRecords) {
            if (isBlank(device.getRpId()) || !hasBytes(device.getUserId()) || !hasBytes(device.getCredentialId())) {
                return signalUnavailable();
            }
            String deviceUserId = encodeBytes(device.getUserId());
            if (rpId == null) {
                rpId = device.getRpId();
                userId = deviceUserId;
            } else if (!rpId.equals(device.getRpId()) || !userId.equals(deviceUserId)) {
                return signalUnavailable();
            }
            acceptedCredentialIds.add(encodeBytes(device.getCredentialId()));
        }

        return json(object(
                field(SIGNAL_AVAILABLE_KEY, true),
                field(RP_ID_KEY, rpId),
                field(USER_ID_KEY, userId),
                field(ALL_ACCEPTED_CREDENTIAL_IDS_KEY, acceptedCredentialIds)));
    }

    private JsonValue signalUnavailable() {
        return json(object(field(SIGNAL_AVAILABLE_KEY, false)));
    }

    private String encodeBytes(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean hasBytes(byte[] bytes) {
        return bytes != null && bytes.length > 0;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    @Override
    @Query(operationDescription = @Operation(
            errors = {
                    @ApiError(
                            code = 500,
                            description = WEBAUTHN_DEVICES_RESOURCE + "error.unexpected.server.error.description")},
            description = WEBAUTHN_DEVICES_RESOURCE + QUERY_DESCRIPTION),
            type = QueryType.FILTER,
            queryableFields = "*"
    )
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        return super.queryCollection(context, request, handler);
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId,
            ReadRequest request) {
        try {
            JsonValue device = findDevice(context, resourceId);
            if (device == null) {
                return new NotFoundException("User WebAuthn device, " + resourceId + ", not found.").asPromise();
            }
            return Promises.newResultPromise(convertValue(device));
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String resourceId,
            UpdateRequest request) {
        try {
            final String userName = contextHelper.getUserId(context);
            List<JsonValue> devices = userDevicesDao.getDeviceProfiles(userName, getRealm(context));
            JsonValue device = findDevice(devices, resourceId);
            if (device == null) {
                return new NotFoundException("User WebAuthn device, " + resourceId + ", not found.").asPromise();
            }

            String deviceName = validatedDeviceName(request);
            device.put(DEVICE_NAME_KEY, deviceName);
            userDevicesDao.saveDeviceProfiles(userName, getRealm(context), devices);
            return Promises.newResultPromise(convertValue(device));
        } catch (BadRequestException e) {
            return e.asPromise();
        } catch (InternalServerErrorException e) {
            return e.asPromise();
        }
    }

    private JsonValue findDevice(Context context, String resourceId) throws InternalServerErrorException {
        final String userName = contextHelper.getUserId(context);
        return findDevice(userDevicesDao.getDeviceProfiles(userName, getRealm(context)), resourceId);
    }

    private JsonValue findDevice(List<JsonValue> devices, String resourceId) {
        for (JsonValue device : devices) {
            if (resourceId.equals(device.get(UUID_KEY).asString())) {
                return device;
            }
        }
        return null;
    }

    private String validatedDeviceName(UpdateRequest request) throws BadRequestException {
        JsonValue content = request.getContent();
        if (content == null || !content.isMap()) {
            throw new BadRequestException("WebAuthn device update must be a JSON object.");
        }

        JsonValue deviceName = content.get(DEVICE_NAME_KEY);
        if (!deviceName.isString()) {
            throw new BadRequestException("deviceName is required.");
        }

        try {
            return WebAuthnDeviceSettings.validateDeviceName(deviceName.asString());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage());
        }
    }

    private void putIfDefined(JsonValue response, JsonValue profile, String fieldName) {
        if (profile.isDefined(fieldName)) {
            response.put(fieldName, profile.get(fieldName).copy());
        }
    }

}
