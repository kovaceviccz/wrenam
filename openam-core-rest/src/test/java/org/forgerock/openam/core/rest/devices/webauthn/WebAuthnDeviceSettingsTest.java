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
 * Header, with the fields enclosed by brackets [] replaced with your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security. All rights reserved.
 */
package org.forgerock.openam.core.rest.devices.webauthn;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.core.rest.devices.DeviceJsonUtils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class WebAuthnDeviceSettingsTest {

    @Test
    public void shouldTrimValidDeviceName() {
        assertEquals(WebAuthnDeviceSettings.validateDeviceName("  Work laptop passkey  "), "Work laptop passkey");
    }

    @Test(dataProvider = "invalidDeviceNames")
    public void shouldRejectInvalidDeviceNames(String deviceName, String expectedMessagePart) {
        try {
            WebAuthnDeviceSettings.validateDeviceName(deviceName);
            fail("Expected invalid device name to fail");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(expectedMessagePart), e.getMessage());
        }
    }

    @Test
    public void shouldSerializeCreatedAt() throws Exception {
        DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils = new DeviceJsonUtils<>(WebAuthnDeviceSettings.class);
        WebAuthnDeviceSettings device = new WebAuthnDeviceSettings(new byte[]{1}, new byte[]{2}, 0L,
                new String[]{"internal"}, false, false, new byte[]{3}, new byte[]{4});
        device.setCreatedAt("2026-06-26T00:00:00Z");

        JsonValue serialized = jsonUtils.toJsonValue(device);

        assertEquals(serialized.get("createdAt").asString(), "2026-06-26T00:00:00Z");
    }

    @DataProvider
    private Object[][] invalidDeviceNames() {
        return new Object[][]{
            {null, "required"},
            {"", "empty"},
            {"   ", "empty"},
            {"Demo\nPasskey", "control characters"},
            {longDeviceName(), "120 characters"}
        };
    }

    private static String longDeviceName() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 121; i++) {
            builder.append('a');
        }
        return builder.toString();
    }
}
