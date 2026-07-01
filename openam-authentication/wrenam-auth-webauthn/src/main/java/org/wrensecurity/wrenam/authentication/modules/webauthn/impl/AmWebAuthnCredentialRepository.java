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
package org.wrensecurity.wrenam.authentication.modules.webauthn.impl;

import jakarta.inject.Inject;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.forgerock.openam.core.rest.devices.DeviceJsonUtils;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDevicesDao;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;

/**
 * AM-backed credential repository used by the WebAuthn server verification implementation.
 */
public class AmWebAuthnCredentialRepository implements WebAuthnCredentialRepository {

    private static final String MISSING_CREDENTIAL_ERROR = "Credential profile no longer exists";

    private final WebAuthnDevicesDao devicesDao;

    private final DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils;

    /**
     * Create an AM-backed WebAuthn credential repository.
     *
     * @param devicesDao AM WebAuthn device profile DAO
     * @param jsonUtils device profile JSON converter
     */
    @Inject
    public AmWebAuthnCredentialRepository(WebAuthnDevicesDao devicesDao,
            DeviceJsonUtils<WebAuthnDeviceSettings> jsonUtils) {
        Reject.ifNull(devicesDao, jsonUtils);
        this.devicesDao = devicesDao;
        this.jsonUtils = jsonUtils;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<WebAuthnDeviceSettings> getCredentialRecords(String username, String realm) throws IOException {
        Reject.ifNull(username, realm);
        return jsonUtils.toDeviceSettingValues(devicesDao.getDeviceProfiles(username, realm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<WebAuthnDeviceSettings> findCredentialRecord(String username, String realm, byte[] credentialId)
            throws IOException {
        Reject.ifNull(username, realm, credentialId);
        for (WebAuthnDeviceSettings credentialRecord : getCredentialRecords(username, realm)) {
            if (Arrays.equals(credentialId, credentialRecord.getCredentialId())) {
                return Optional.of(credentialRecord);
            }
        }
        return Optional.empty();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void storeCredentialRecord(String username, String realm, WebAuthnDeviceSettings credentialRecord)
            throws IOException {
        Reject.ifNull(username, realm, credentialRecord, credentialRecord.getCredentialId());
        List<WebAuthnDeviceSettings> profiles =
                jsonUtils.toDeviceSettingValues(devicesDao.getDeviceProfiles(username, realm));
        if (!replaceCredentialRecord(profiles, credentialRecord)) {
            profiles.add(credentialRecord);
        }
        devicesDao.saveDeviceProfiles(username, realm, jsonUtils.toJsonValues(profiles));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateCredentialRecord(String username, String realm, WebAuthnDeviceSettings updated)
            throws IOException {
        Reject.ifNull(username, realm, updated, updated.getCredentialId());
        List<WebAuthnDeviceSettings> currentProfiles =
                jsonUtils.toDeviceSettingValues(devicesDao.getDeviceProfiles(username, realm));
        if (!replaceCredentialRecord(currentProfiles, updated)) {
            throw new IOException(MISSING_CREDENTIAL_ERROR);
        }

        // Re-read before write to reduce delete-vs-update races where a credential is removed concurrently.
        List<WebAuthnDeviceSettings> latestProfiles =
                jsonUtils.toDeviceSettingValues(devicesDao.getDeviceProfiles(username, realm));
        if (!replaceCredentialRecord(latestProfiles, updated)) {
            throw new IOException(MISSING_CREDENTIAL_ERROR);
        }
        devicesDao.saveDeviceProfiles(username, realm, jsonUtils.toJsonValues(latestProfiles));
    }

    private boolean replaceCredentialRecord(List<WebAuthnDeviceSettings> profiles, WebAuthnDeviceSettings updated) {
        byte[] updatedId = updated.getCredentialId();
        // Expected profile count is small per user, so linear scan is simpler and fast enough here.
        for (int i = 0; i < profiles.size(); i++) {
            if (Arrays.equals(updatedId, profiles.get(i).getCredentialId())) {
                profiles.set(i, updated);
                return true;
            }
        }
        return false;
    }
}
