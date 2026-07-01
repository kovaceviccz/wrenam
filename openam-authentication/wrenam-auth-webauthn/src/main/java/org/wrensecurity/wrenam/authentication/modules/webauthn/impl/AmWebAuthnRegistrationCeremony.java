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
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnChallenge;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAccountRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialVerifier;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRecoveryCodes;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRegistrationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.registration.PublicKeyCredentialCreationOptions;

/**
 * Implement the AM-backed WebAuthn registration ceremony. Own the full ceremony lifecycle by composing the
 * library-specific registration verifier with the AM-specific account identity, credential store, and recovery code
 * generation.
 */
public class AmWebAuthnRegistrationCeremony implements WebAuthnRegistrationCeremony {

    private final WebAuthnAccountRepository accountRepository;

    private final WebAuthnCredentialRepository credentialRepository;

    private final WebAuthnCredentialVerifier verifier;

    private final WebAuthnRecoveryCodes recoveryCodes;

    private final WebAuthnChallenge challenge;

    /**
     * Create an AM-backed WebAuthn registration ceremony.
     *
     * @param accountRepository account repository
     * @param credentialRepository credential repository
     * @param verifier WebAuthn attestation verifier
     * @param recoveryCodes recovery code service
     * @param challenge WebAuthn challenge service
     */
    @Inject
    public AmWebAuthnRegistrationCeremony(WebAuthnAccountRepository accountRepository,
            WebAuthnCredentialRepository credentialRepository, WebAuthnCredentialVerifier verifier,
            WebAuthnRecoveryCodes recoveryCodes, WebAuthnChallenge challenge) {
        Reject.ifNull(accountRepository, credentialRepository, verifier, recoveryCodes, challenge);
        this.accountRepository = accountRepository;
        this.credentialRepository = credentialRepository;
        this.verifier = verifier;
        this.recoveryCodes = recoveryCodes;
        this.challenge = challenge;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PublicKeyCredentialCreationOptions initiate(String realm, String username, String rpId, String rpName,
            int timeout, String userVerification, String authenticatorAttachment, String residentKey)
            throws WebAuthnCeremonyException {
        Reject.ifNull(realm, username, rpId);
        try {
            // §5.4.3 / §6.1 User Handle: send a stable, non-personally-identifying account identifier as user.id.
            byte[] userHandle = accountRepository.getUserHandle(username, realm);
            String displayName = accountRepository.getDisplayName(username, realm);
            // §7.1 step 1 / §5.4: the challenge, relying party, and user identity are all server-originated inputs
            // to navigator.credentials.create().
            return new PublicKeyCredentialCreationOptions.Builder()
                    .authenticatorAttachment(authenticatorAttachment)
                    .residentKey(residentKey)
                    .userVerification(userVerification)
                    // §13.4.3 Cryptographic Challenges: a fresh random challenge per ceremony.
                    .challenge(challenge.generate())
                    .challengeIssuedAtMillis(challenge.issuedAtMillis())
                    // §5.4 excludeCredentials: stop the authenticator from creating a second credential on an
                    // authenticator already registered to this account.
                    .excludeCredentials(credentialRepository.getCredentialRecords(username, realm))
                    .rpId(rpId)
                    .rpName(rpName)
                    .timeout(timeout)
                    .userId(userHandle)
                    .userName(username)
                    .displayName(displayName)
                    .build();
        } catch (IOException | IllegalArgumentException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.FAILED_BUILDING_REGISTRATION_OPTIONS, e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public WebAuthnDeviceSettings verify(PublicKeyCredentialCreationOptions options, String origin,
            String credentialJson) throws WebAuthnCeremonyException {
        // §7.1 steps 3-26: verify the registration response (challenge, origin, RP ID hash, flags, and the
        // supported "none" attestation statement) and derive the credential record to be stored.
        return verifier.verifyRegistration(options, origin, credentialJson);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] finalizeRegistration(String username, String realm, WebAuthnDeviceSettings credentialRecord)
            throws WebAuthnCeremonyException {
        Reject.ifNull(username, realm, credentialRecord);
        try {
            recoveryCodes.addRecoveryCodes(credentialRecord);
        } catch (CodeException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.RECOVERY_CODE_GENERATION_FAILED, e);
        }
        // Recovery codes are revealed exactly once on the next screen, so the stored record is sealed immediately:
        // the self-service device API will never disclose these values again, only their count.
        credentialRecord.setRecoveryCodesSealed(true);
        try {
            // WebAuthn Level 3 §7.1 step 26: the RP should verify the credential ID is not already registered to
            // any user. AM stores WebAuthn credentials in per-user device profiles, which may be encrypted, so a
            // realm-wide uniqueness check would require scanning and deserializing every user's profiles here.
            // That heavy scan is intentionally not performed by this authentication module.
            // §7.1 steps 27-29: associate the new credential with the user account and store it.
            credentialRepository.storeCredentialRecord(username, realm, credentialRecord);
        } catch (IOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.CREDENTIAL_PERSIST_FAILED, e);
        }
        return credentialRecord.getRecoveryCodes();
    }
}
