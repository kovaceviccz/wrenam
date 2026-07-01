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
package org.wrensecurity.wrenam.authentication.modules.webauthn.core;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;

/**
 * Credential repository operations required by WebAuthn server verification.
 */
public interface WebAuthnCredentialRepository {

    /**
     * Get all WebAuthn credential records for a user.
     *
     * @param username credential owner
     * @param realm realm containing the credential owner
     * @return stored credential records
     * @throws IOException if credential records cannot be read
     */
    List<WebAuthnDeviceSettings> getCredentialRecords(String username, String realm) throws IOException;

    /**
     * Find one WebAuthn credential record by credential ID.
     *
     * @param username credential owner
     * @param realm realm containing the credential owner
     * @param credentialId WebAuthn credential identifier
     * @return matching credential record, or empty when no record exists
     * @throws IOException if credential records cannot be read
     */
    Optional<WebAuthnDeviceSettings> findCredentialRecord(String username, String realm, byte[] credentialId)
            throws IOException;

    /**
     * Store a verified WebAuthn credential record. Replace the matching stored record when one already exists.
     *
     * @param username credential owner
     * @param realm realm containing the credential owner
     * @param credentialRecord credential record to persist
     * @throws IOException if the credential record cannot be saved
     */
    void storeCredentialRecord(String username, String realm, WebAuthnDeviceSettings credentialRecord)
            throws IOException;

    /**
     * Update an existing WebAuthn credential record.
     *
     * @param username credential owner
     * @param realm realm containing the credential owner
     * @param updated updated credential record
     * @throws IOException if the credential record cannot be updated
     */
    void updateCredentialRecord(String username, String realm, WebAuthnDeviceSettings updated) throws IOException;
}
