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
import org.wrensecurity.wrenam.authentication.modules.webauthn.registration.PublicKeyCredentialCreationOptions;

/**
 * Define the WebAuthn registration ceremony lifecycle: produce server-originated creation options
 * ({@link #initiate}), verify the attestation response ({@link #verify}), and store the resulting credential
 * ({@link #finalizeRegistration}). The intermediate step exists because registration is interactive: the user may
 * name the device before the credential is persisted.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn Level 3 &sect;7.1</a>
 */
public interface WebAuthnRegistrationCeremony {

    /**
     * Build the {@code PublicKeyCredentialCreationOptions} handed to {@code navigator.credentials.create()}:
     * a fresh challenge, relying party and user identity, and the credentials to exclude from re-registration.
     *
     * @param realm realm containing the registering user
     * @param username registering username
     * @param rpId relying party identifier
     * @param rpName relying party display name
     * @param timeout timeout hint in milliseconds
     * @param userVerification relying party user verification requirement
     * @param authenticatorAttachment requested authenticator attachment modality
     * @param residentKey relying party resident key requirement
     * @return creation options for {@code navigator.credentials.create()}
     * @throws WebAuthnCeremonyException if creation options cannot be built
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-credentialcreationoptions-extension">
     *     WebAuthn Level 3 &sect;5.4</a>
     */
    PublicKeyCredentialCreationOptions initiate(String realm, String username, String rpId, String rpName,
            int timeout, String userVerification, String authenticatorAttachment, String residentKey)
            throws WebAuthnCeremonyException;

    /**
     * Verify the attestation response and produce the credential record to be stored. Does not persist.
     *
     * @param options server-originated creation options
     * @param origin configured relying party origin
     * @param credentialJson browser credential response JSON
     * @return verified credential record to store
     * @throws WebAuthnCeremonyException if attestation verification fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">WebAuthn Level 3 &sect;7.1</a>
     */
    WebAuthnDeviceSettings verify(PublicKeyCredentialCreationOptions options, String origin, String credentialJson)
            throws WebAuthnCeremonyException;

    /**
     * Associate the verified credential with the user account and persist it, generating the one-time recovery
     * codes that are revealed to the user exactly once.
     *
     * @param username registering username
     * @param realm realm containing the registering user
     * @param credentialRecord verified credential record to store
     * @return the freshly generated recovery codes to present to the user
     * @throws WebAuthnCeremonyException if credential persistence fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">
     *     WebAuthn Level 3 &sect;7.1 steps 27-29</a>
     */
    String[] finalizeRegistration(String username, String realm, WebAuthnDeviceSettings credentialRecord)
            throws WebAuthnCeremonyException;
}
