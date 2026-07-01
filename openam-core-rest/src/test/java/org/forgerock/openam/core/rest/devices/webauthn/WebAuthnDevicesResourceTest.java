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
 * Copyright 2026 Wren Security. All rights reserved.
 */
package org.forgerock.openam.core.rest.devices.webauthn;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import java.util.ArrayList;
import java.util.List;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.Requests;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.core.rest.devices.DeviceJsonUtils;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class WebAuthnDevicesResourceTest {

    private static final String USER_ID = "demo";

    @Mock
    private WebAuthnDevicesDao dao;

    @Mock
    private ContextHelper contextHelper;

    @Mock
    private RecoveryCodeGenerator recoveryCodeGenerator;

    private DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils;

    private WebAuthnDevicesResource resource;

    private RealmTestHelper realmTestHelper;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        given(contextHelper.getUserId(any(Context.class))).willReturn(USER_ID);
        jsonUtils = new DeviceJsonUtils<>(WebAuthnDeviceSettings.class);
        resource = new WebAuthnDevicesResource(dao, contextHelper, recoveryCodeGenerator, jsonUtils);
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    @Test
    public void shouldQueryMultipleDevicesAndExposeManagementDataWithRecoveryCodes() throws Exception {
        QueryRequest request = Requests.newQueryRequest("");
        QueryResourceHandler handler = mock(QueryResourceHandler.class);
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        resource.queryCollection(ctx(), request, handler).getOrThrowUninterruptibly();

        ArgumentCaptor<ResourceResponse> responseCaptor = ArgumentCaptor.forClass(ResourceResponse.class);
        verify(handler, times(2)).handleResource(responseCaptor.capture());
        JsonValue firstDevice = responseCaptor.getAllValues().get(0).getContent();
        assertEquals(firstDevice.get("uuid").asString(), "UUID_1");
        assertFalse(firstDevice.isDefined("id"));
        assertEquals(firstDevice.get("deviceName").asString(), "Laptop passkey");
        assertEquals(firstDevice.get("createdAt").asString(), "2026-06-26T00:00:00Z");
        assertEquals(firstDevice.get("recoveryCodes").asList(), List.of("CODE-1", "CODE-2"));
        assertFalse(firstDevice.isDefined("displayName"));
        assertFalse(firstDevice.isDefined("passkeyType"));
        assertFalse(firstDevice.isDefined("attestationLevel"));
        assertFalse(firstDevice.isDefined("credentialId"));
        assertFalse(firstDevice.isDefined("publicKey"));
        assertFalse(firstDevice.isDefined("attestationObject"));
        assertFalse(firstDevice.isDefined("attestationClientDataJSON"));
    }

    @Test
    public void shouldHideRecoveryCodesForSealedDeviceAndExposeRemainingCount() throws Exception {
        ReadRequest request = Requests.newReadRequest("UUID_SEALED");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(sealedDevices());

        ResourceResponse response = resource.readInstance(ctx(), "UUID_SEALED", request).getOrThrowUninterruptibly();

        JsonValue content = response.getContent();
        assertFalse(content.isDefined("recoveryCodes"), "Sealed device must not disclose recovery code values");
        assertTrue(content.get("recoveryCodesSealed").asBoolean());
        assertEquals(content.get("recoveryCodesRemaining").asInteger(), Integer.valueOf(2));
    }

    @Test
    public void shouldRegenerateRecoveryCodesReturningPlaintextOnceAndPreservingSealedState() throws Exception {
        List<JsonValue> devices = sealedDevices();
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices);
        given(recoveryCodeGenerator.generateCodes(anyInt(), any(), anyBoolean()))
                .willReturn(new String[]{"NEW-1", "NEW-2", "NEW-3"});
        ActionRequest request = Requests.newActionRequest("webauthn", "regenerateRecoveryCodes");

        ActionResponse response = resource.actionInstance(ctx(), "UUID_SEALED", request).getOrThrowUninterruptibly();

        JsonValue content = response.getJsonContent();
        assertEquals(content.get("recoveryCodes").asList(), List.of("NEW-1", "NEW-2", "NEW-3"));
        assertEquals(content.get("recoveryCodesRemaining").asInteger(), Integer.valueOf(3));
        assertTrue(content.get("recoveryCodesSealed").asBoolean(), "Regeneration must preserve the sealed state");

        ArgumentCaptor<List> devicesCaptor = ArgumentCaptor.forClass(List.class);
        verify(dao).saveDeviceProfiles(anyString(), anyString(), devicesCaptor.capture());
        JsonValue saved = (JsonValue) devicesCaptor.getValue().get(0);
        assertEquals(saved.get("recoveryCodes").asList(), List.of("NEW-1", "NEW-2", "NEW-3"));
        assertTrue(saved.get("recoveryCodesSealed").asBoolean());
    }

    @Test
    public void shouldRejectRegenerateOfUnknownDevice() throws Exception {
        ActionRequest request = Requests.newActionRequest("webauthn", "regenerateRecoveryCodes");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        try {
            resource.actionInstance(ctx(), "UNKNOWN", request).getOrThrowUninterruptibly();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), ResourceException.NOT_FOUND);
            verify(dao, never()).saveDeviceProfiles(anyString(), anyString(), any());
            return;
        }
        throw new AssertionError("Expected regenerate of unknown WebAuthn device to fail");
    }

    @Test
    public void shouldRejectUnsupportedAction() throws Exception {
        ActionRequest request = Requests.newActionRequest("webauthn", "someOtherAction");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        try {
            resource.actionInstance(ctx(), "UUID_1", request).getOrThrowUninterruptibly();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), ResourceException.NOT_SUPPORTED);
            return;
        }
        throw new AssertionError("Expected unsupported action to fail");
    }

    @Test
    public void shouldReturnSignalAllAcceptedCredentialsPayload() throws Exception {
        ActionRequest request = Requests.newActionRequest("webauthn", "signalAllAcceptedCredentials");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(signalDevices());

        ActionResponse response = resource.actionCollection(ctx(), request).getOrThrowUninterruptibly();

        JsonValue content = response.getJsonContent();
        assertTrue(content.get("signalAvailable").asBoolean());
        assertEquals(content.get("rpId").asString(), "am.example.com");
        assertEquals(content.get("userId").asString(), "AQID");
        assertEquals(content.get("allAcceptedCredentialIds").asList(), List.of("BAU", "Bgc"));
    }

    @Test
    public void shouldNotReturnSignalPayloadWhenCredentialMetadataIsIncomplete() throws Exception {
        ActionRequest request = Requests.newActionRequest("webauthn", "signalAllAcceptedCredentials");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(legacySignalDevices());

        ActionResponse response = resource.actionCollection(ctx(), request).getOrThrowUninterruptibly();

        JsonValue content = response.getJsonContent();
        assertFalse(content.get("signalAvailable").asBoolean());
        assertFalse(content.isDefined("rpId"));
        assertFalse(content.isDefined("userId"));
        assertFalse(content.isDefined("allAcceptedCredentialIds"));
    }

    @Test
    public void shouldReadSingleDeviceById() throws Exception {
        ReadRequest request = Requests.newReadRequest("UUID_2");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        ResourceResponse response = resource.readInstance(ctx(), "UUID_2", request).getOrThrowUninterruptibly();

        assertEquals(response.getId(), "UUID_2");
        assertEquals(response.getContent().get("deviceName").asString(), "Security key");
        assertEquals(response.getContent().get("recoveryCodes").asList(), List.of("CODE-3"));
        assertFalse(response.getContent().isDefined("passkeyType"));
    }

    @Test
    public void shouldUpdateDeviceNameWithoutDroppingCredentialMaterial() throws Exception {
        UpdateRequest request = Requests.newUpdateRequest("UUID_2",
                json(object(field("deviceName", "  Blue security key  "))));
        List<JsonValue> devices = devices();
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices);

        ResourceResponse response = resource.updateInstance(ctx(), "UUID_2", request).getOrThrowUninterruptibly();

        assertEquals(response.getContent().get("deviceName").asString(), "Blue security key");
        assertFalse(response.getContent().isDefined("displayName"));
        ArgumentCaptor<List> devicesCaptor = ArgumentCaptor.forClass(List.class);
        verify(dao).saveDeviceProfiles(anyString(), anyString(), devicesCaptor.capture());
        JsonValue updatedDevice = (JsonValue) devicesCaptor.getValue().get(1);
        assertEquals(updatedDevice.get("deviceName").asString(), "Blue security key");
        assertEquals(updatedDevice.get("credentialId").asString(), "SECRET_2");
        assertEquals(updatedDevice.get("publicKey").asString(), "PUBLIC_KEY_2");
    }

    @Test(dataProvider = "invalidUpdatePayloads")
    public void shouldRejectInvalidDeviceNameUpdates(JsonValue payload, String expectedMessagePart) throws Exception {
        UpdateRequest request = Requests.newUpdateRequest("UUID_2", payload);
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        try {
            resource.updateInstance(ctx(), "UUID_2", request).getOrThrowUninterruptibly();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(e.getMessage().contains(expectedMessagePart), e.getMessage());
            verify(dao, never()).saveDeviceProfiles(anyString(), anyString(), any());
            return;
        }
        throw new AssertionError("Expected invalid WebAuthn device update to fail");
    }

    @Test
    public void shouldRejectUpdateOfUnknownDevice() throws Exception {
        UpdateRequest request = Requests.newUpdateRequest("UNKNOWN",
                json(object(field("deviceName", "Unknown passkey"))));
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        try {
            resource.updateInstance(ctx(), "UNKNOWN", request).getOrThrowUninterruptibly();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), ResourceException.NOT_FOUND);
            verify(dao, never()).saveDeviceProfiles(anyString(), anyString(), any());
            return;
        }
        throw new AssertionError("Expected unknown WebAuthn device update to fail");
    }

    @Test
    public void shouldDeleteDeviceAndExposeManagementDataWithRecoveryCodes() throws Exception {
        DeleteRequest request = Requests.newDeleteRequest("UUID_2");
        List<JsonValue> devices = devices();
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices);

        ResourceResponse response = resource.deleteInstance(ctx(), "UUID_2", request).getOrThrowUninterruptibly();

        assertEquals(response.getId(), "UUID_2");
        assertEquals(response.getContent().get("deviceName").asString(), "Security key");
        assertEquals(response.getContent().get("recoveryCodes").asList(), List.of("CODE-3"));
        assertFalse(response.getContent().isDefined("displayName"));
        assertFalse(response.getContent().isDefined("credentialId"));
        assertFalse(response.getContent().isDefined("publicKey"));
        assertFalse(response.getContent().isDefined("attestationObject"));
        assertFalse(response.getContent().isDefined("attestationClientDataJSON"));
        ArgumentCaptor<List> devicesCaptor = ArgumentCaptor.forClass(List.class);
        verify(dao).saveDeviceProfiles(anyString(), anyString(), devicesCaptor.capture());
        assertEquals(devicesCaptor.getValue().size(), 1);
        JsonValue remainingDevice = (JsonValue) devicesCaptor.getValue().get(0);
        assertEquals(remainingDevice.get("uuid").asString(), "UUID_1");
    }

    @Test
    public void shouldRejectDeleteOfUnknownDevice() throws Exception {
        DeleteRequest request = Requests.newDeleteRequest("UNKNOWN");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        try {
            resource.deleteInstance(ctx(), "UNKNOWN", request).getOrThrowUninterruptibly();
        } catch (ResourceException e) {
            assertEquals(e.getCode(), ResourceException.NOT_FOUND);
            verify(dao, never()).saveDeviceProfiles(anyString(), anyString(), any());
            return;
        }
        throw new AssertionError("Expected unknown WebAuthn device delete to fail");
    }

    @Test(expectedExceptions = ResourceException.class)
    public void shouldRejectReadOfUnknownDevice() throws Exception {
        ReadRequest request = Requests.newReadRequest("UNKNOWN");
        given(dao.getDeviceProfiles(anyString(), anyString())).willReturn(devices());

        resource.readInstance(ctx(), "UNKNOWN", request).getOrThrowUninterruptibly();
    }

    @DataProvider
    private Object[][] invalidUpdatePayloads() {
        return new Object[][]{
            {json(object()), "deviceName is required"},
            {json(object(field("deviceName", ""))), "must not be empty"},
            {json(object(field("deviceName", "   "))), "must not be empty"},
            {json(object(field("deviceName", 42))), "deviceName is required"},
            {json(object(field("deviceName", "Demo\nPasskey"))), "control characters"},
            {json(object(field("deviceName", longDeviceName()))), "120 characters"}
        };
    }

    private String longDeviceName() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 121; i++) {
            builder.append('a');
        }
        return builder.toString();
    }

    private Context ctx() throws SSOException {
        SSOTokenContext mockSubjectContext = mock(SSOTokenContext.class);
        given(mockSubjectContext.getCallerSSOToken()).willReturn(mock(SSOToken.class));
        return ClientContext.newInternalClientContext(new RealmContext(mock(SSOTokenContext.class), Realm.root()));
    }

    private List<JsonValue> devices() {
        List<JsonValue> devices = new ArrayList<>();
        devices.add(json(object(
                field("uuid", "UUID_1"),
                field("deviceName", "Laptop passkey"),
                field("credentialId", "SECRET_1"),
                field("publicKey", "PUBLIC_KEY_1"),
                field("createdAt", "2026-06-26T00:00:00Z"),
                field("aaguid", "AAAAAAAAAAAAAAAAAAAAAA"),
                field("model", "Platform authenticator"),
                field("attestationCertificates", List.of("cert-fingerprint")),
                field("attestationLevel", "attested"),
                field("passkeyType", "synced"),
                field("recoveryCodes", List.of("CODE-1", "CODE-2")),
                field("transports", List.of("internal")))));
        devices.add(json(object(
                field("uuid", "UUID_2"),
                field("deviceName", "Security key"),
                field("credentialId", "SECRET_2"),
                field("publicKey", "PUBLIC_KEY_2"),
                field("attestationLevel", "notAttested"),
                field("passkeyType", "deviceBound"),
                field("recoveryCodes", List.of("CODE-3")),
                field("transports", List.of("usb")))));
        return devices;
    }

    private List<JsonValue> sealedDevices() {
        List<JsonValue> devices = new ArrayList<>();
        devices.add(json(object(
                field("uuid", "UUID_SEALED"),
                field("deviceName", "Laptop passkey"),
                field("credentialId", "SECRET_1"),
                field("publicKey", "PUBLIC_KEY_1"),
                field("passkeyType", "synced"),
                field("recoveryCodesSealed", true),
                field("recoveryCodes", List.of("CODE-1", "CODE-2")),
                field("transports", List.of("internal")))));
        return devices;
    }

    private List<JsonValue> signalDevices() throws Exception {
        WebAuthnDeviceSettings firstDevice = signalDevice(new byte[]{4, 5});
        WebAuthnDeviceSettings secondDevice = signalDevice(new byte[]{6, 7});
        return jsonUtils.toJsonValues(List.of(firstDevice, secondDevice));
    }

    private List<JsonValue> legacySignalDevices() throws Exception {
        return jsonUtils.toJsonValues(List.of(new WebAuthnDeviceSettings(new byte[]{4, 5}, new byte[]{2}, 0L,
                new String[]{"internal"}, false, false, new byte[]{3}, new byte[]{4})));
    }

    private WebAuthnDeviceSettings signalDevice(byte[] credentialId) {
        WebAuthnDeviceSettings device = new WebAuthnDeviceSettings(credentialId, new byte[]{2}, 0L,
                new String[]{"internal"}, false, false, new byte[]{3}, new byte[]{4});
        device.setRpId("am.example.com");
        device.setUserId(new byte[]{1, 2, 3});
        return device;
    }
}
