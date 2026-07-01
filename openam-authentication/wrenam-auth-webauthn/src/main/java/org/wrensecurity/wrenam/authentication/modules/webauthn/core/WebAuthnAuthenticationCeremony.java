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

import org.wrensecurity.wrenam.authentication.modules.webauthn.authentication.PublicKeyCredentialRequestOptions;

/**
 * Define the WebAuthn authentication ceremony lifecycle: produce server-originated assertion options
 * ({@link #initiate}) and verify the authenticator's response ({@link #complete}). Login modules drive the
 * ceremony but contain none of its WebAuthn logic.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 &sect;7.2</a>
 */
public interface WebAuthnAuthenticationCeremony {

    /**
     * Build the {@code PublicKeyCredentialRequestOptions} handed to {@code navigator.credentials.get()}:
     * a fresh challenge, the relying party scope, and (outside the discoverable-credential flow) the
     * credentials allowed for the identified account.
     *
     * @param realm realm containing the authenticating user
     * @param username authenticating username, or {@code null} for a discoverable credential ceremony
     * @param rpId relying party identifier
     * @param timeout timeout hint in milliseconds
     * @param userVerification relying party user verification requirement
     * @param discoverable whether the ceremony uses discoverable credentials
     * @return request options for {@code navigator.credentials.get()}
     * @throws WebAuthnCeremonyException if request options cannot be built
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-assertion-options">WebAuthn Level 3 &sect;5.5</a>
     */
    PublicKeyCredentialRequestOptions initiate(String realm, String username, String rpId, int timeout,
            String userVerification, boolean discoverable) throws WebAuthnCeremonyException;

    /**
     * Verify the assertion response, resolve the credential owner, and persist post-assertion state (sign
     * count, backup state) as a single atomic step.
     *
     * @param options server-originated assertion options
     * @param origin configured relying party origin
     * @param credentialJson browser credential response JSON
     * @param username authenticating username, or {@code null} for a discoverable credential ceremony
     * @param realm realm containing the authenticating user
     * @return the resolved credential owner
     * @throws WebAuthnCeremonyException if assertion verification fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 &sect;7.2</a>
     */
    String complete(PublicKeyCredentialRequestOptions options, String origin, String credentialJson,
            String username, String realm) throws WebAuthnCeremonyException;
}
