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

import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.wrensecurity.wrenam.authentication.modules.webauthn.authentication.PublicKeyCredentialRequestOptions;
import org.wrensecurity.wrenam.authentication.modules.webauthn.registration.PublicKeyCredentialCreationOptions;

/**
 * Boundary for verifying WebAuthn ceremony responses against the server-issued options.
 *
 * <p>Keep this deliberately small: it keeps server-library parsing and verification out of the AM ceremony classes
 * without pretending the server library is a configurable runtime plugin.
 */
public interface WebAuthnCredentialVerifier {

    /**
     * Verify a registration (attestation) response and produce the credential record to store.
     *
     * @param options server-originated creation options
     * @param origin configured relying party origin
     * @param credentialJson browser credential response JSON
     * @return verified credential record to store
     * @throws WebAuthnCeremonyException if attestation verification fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn Level 3 &sect;7.1</a>
     */
    WebAuthnDeviceSettings verifyRegistration(PublicKeyCredentialCreationOptions options, String origin,
            String credentialJson) throws WebAuthnCeremonyException;

    /**
     * Verify an authentication (assertion) response, persist authenticator state, and resolve the credential owner.
     *
     * @param options server-originated assertion options
     * @param origin configured relying party origin
     * @param credentialJson browser credential response JSON
     * @param username authenticating username, or {@code null} for a discoverable credential ceremony
     * @param realm realm containing the authenticating user
     * @return resolved credential owner
     * @throws WebAuthnCeremonyException if assertion verification fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 &sect;7.2</a>
     */
    String verifyAuthentication(PublicKeyCredentialRequestOptions options, String origin,
            String credentialJson, String username, String realm)
            throws WebAuthnCeremonyException;
}
