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
import java.util.List;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnChallenge;
import org.wrensecurity.wrenam.authentication.modules.webauthn.authentication.PublicKeyCredentialRequestOptions;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAuthenticationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialVerifier;

/**
 * Implement the AM-backed WebAuthn authentication ceremony. Own the full ceremony lifecycle: composing the
 * library-specific assertion verifier with the AM credential store, and persisting post-assertion authenticator state
 * as part of completing the ceremony.
 */
public class AmWebAuthnAuthenticationCeremony implements WebAuthnAuthenticationCeremony {

    private final WebAuthnCredentialRepository credentialRepository;

    private final WebAuthnCredentialVerifier verifier;

    private final WebAuthnChallenge challenge;

    /**
     * Create an AM-backed WebAuthn authentication ceremony.
     *
     * @param credentialRepository credential repository
     * @param verifier WebAuthn assertion verifier
     * @param challenge WebAuthn challenge service
     */
    @Inject
    public AmWebAuthnAuthenticationCeremony(WebAuthnCredentialRepository credentialRepository,
            WebAuthnCredentialVerifier verifier, WebAuthnChallenge challenge) {
        Reject.ifNull(credentialRepository, verifier, challenge);
        this.credentialRepository = credentialRepository;
        this.verifier = verifier;
        this.challenge = challenge;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PublicKeyCredentialRequestOptions initiate(String realm, String username, String rpId, int timeout,
            String userVerification, boolean discoverable) throws WebAuthnCeremonyException {
        Reject.ifNull(realm, rpId);
        try {
            PublicKeyCredentialRequestOptions.Builder builder = new PublicKeyCredentialRequestOptions.Builder()
                    // §13.4.3 Cryptographic Challenges: a fresh random challenge bounds the ceremony and defends
                    // against assertion replay.
                    .challenge(challenge.generate())
                    .challengeIssuedAtMillis(challenge.issuedAtMillis())
                    // §5.5 Options for Assertion Generation: scope the assertion to the configured relying party.
                    .rpId(rpId)
                    .timeout(timeout)
                    // §5.5 userVerification: the relying party's requirement for authenticator user verification.
                    .userVerification(userVerification);
            if (!discoverable) {
                // §7.2 step 5: outside the discoverable-credential flow, limit the assertion to credentials
                // registered for the identified account.
                List<WebAuthnDeviceSettings> allowCredentials =
                        credentialRepository.getCredentialRecords(username, realm);
                if (allowCredentials == null || allowCredentials.isEmpty()) {
                    throw new WebAuthnCeremonyException(WebAuthnCeremonyError.NO_REGISTERED_CREDENTIALS);
                }
                builder.allowCredentials(allowCredentials);
            }
            return builder.build();
        } catch (IOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.FAILED_PREPARING_REQUEST_OPTIONS, e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String complete(PublicKeyCredentialRequestOptions options, String origin, String credentialJson,
            String username, String realm) throws WebAuthnCeremonyException {
        // §7.2 steps 7-22: verify the response type, challenge, origin, RP ID hash, flags, and signature.
        return verifier.verifyAuthentication(options, origin, credentialJson, username, realm);
    }
}
