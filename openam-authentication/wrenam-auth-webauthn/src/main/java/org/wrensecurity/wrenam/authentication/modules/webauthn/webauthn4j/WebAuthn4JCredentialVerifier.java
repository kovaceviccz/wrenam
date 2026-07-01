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
 * Copyright 2025-2026 Wren Security. All rights reserved.
 */
package org.wrensecurity.wrenam.authentication.modules.webauthn.webauthn4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadOriginException;
import com.webauthn4j.verifier.exception.BadRpIdException;
import com.webauthn4j.verifier.exception.CrossOriginException;
import com.webauthn4j.verifier.exception.VerificationException;
import jakarta.inject.Inject;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnChallenge;
import org.wrensecurity.wrenam.authentication.modules.webauthn.authentication.PublicKeyCredentialRequestOptions;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAccountRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialVerifier;
import org.wrensecurity.wrenam.authentication.modules.webauthn.registration.PublicKeyCredentialCreationOptions;

/**
 * WebAuthn ceremony verification implemented with WebAuthn4J.
 *
 * This class coordinates WebAuthn4J parsing and verification with the module repositories. WebAuthn4J-specific
 * credential conversion lives in this package so AM ceremony classes remain independent of the server library.
 */
public class WebAuthn4JCredentialVerifier implements WebAuthnCredentialVerifier {

    private final WebAuthnCredentialRepository credentialRepository;

    private final WebAuthnAccountRepository accountRepository;

    private final WebAuthnChallenge challenge;

    private final WebAuthn4JCredentialMapper credentialMapper;

    private final ObjectMapper objectMapper;

    /**
     * Create a WebAuthn4J-backed verifier.
     *
     * @param credentialRepository credential repository
     * @param accountRepository account repository
     * @param challenge WebAuthn challenge service
     * @param credentialMapper WebAuthn4J credential mapper
     */
    @Inject
    public WebAuthn4JCredentialVerifier(WebAuthnCredentialRepository credentialRepository,
            WebAuthnAccountRepository accountRepository, WebAuthnChallenge challenge,
            WebAuthn4JCredentialMapper credentialMapper) {
        this(credentialRepository, accountRepository, challenge, credentialMapper, new ObjectMapper());
    }

    WebAuthn4JCredentialVerifier(WebAuthnCredentialRepository credentialRepository,
            WebAuthnAccountRepository accountRepository, WebAuthnChallenge challenge,
            WebAuthn4JCredentialMapper credentialMapper, ObjectMapper objectMapper) {
        Reject.ifNull(credentialRepository, accountRepository, challenge, credentialMapper, objectMapper);
        this.credentialRepository = credentialRepository;
        this.accountRepository = accountRepository;
        this.challenge = challenge;
        this.credentialMapper = credentialMapper;
        this.objectMapper = objectMapper;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public WebAuthnDeviceSettings verifyRegistration(PublicKeyCredentialCreationOptions options, String origin,
            String credentialJson)
            throws WebAuthnCeremonyException {
        Reject.ifNull(options, origin, credentialJson);
        challenge.assertNotExpired(options.getChallengeIssuedAtMillis(), options.getTimeout());

        JsonNode root;
        RegistrationData registrationData;
        WebAuthnManager webAuthnManager = newWebAuthnManager();
        try {
            root = objectMapper.readTree(credentialJson);
            registrationData = webAuthnManager.parseRegistrationResponseJSON(credentialJson);
        } catch (JsonProcessingException | RuntimeException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.REGISTRATION_PARSE_FAILED, e);
        }

        try {
            webAuthnManager.verify(registrationData, registrationParameters(options, origin));
            return credentialMapper.toDeviceSettings(registrationData, root);
        } catch (DataConversionException | VerificationException | IllegalArgumentException | AssertionError e) {
            throw verificationFailure(WebAuthnCeremonyError.REGISTRATION_VERIFICATION_FAILED, e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String verifyAuthentication(PublicKeyCredentialRequestOptions options, String origin,
            String credentialJson, String username, String realm)
            throws WebAuthnCeremonyException {
        Reject.ifNull(options, origin, credentialJson, realm);
        challenge.assertNotExpired(options.getChallengeIssuedAtMillis(), options.getTimeout());

        AuthenticationData authenticationData;
        WebAuthnManager webAuthnManager = newWebAuthnManager();
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(credentialJson);
        } catch (RuntimeException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.ASSERTION_PARSE_FAILED, e);
        }

        byte[] credentialId = authenticationData.getCredentialId();
        // WebAuthn Level 3 §7.2 step 3: the response credential ID is the key used for the server-side
        // credential lookup; an assertion without one cannot identify a stored public key credential source.
        if (credentialId == null || credentialId.length == 0) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.MISSING_CREDENTIAL_ID);
        }

        String effectiveUser = resolveUsername(username, realm, authenticationData);
        WebAuthnDeviceSettings credentialRecordSettings = requireCredentialRecord(realm, effectiveUser, credentialId);
        verifyAuthenticationData(webAuthnManager, options, origin, authenticationData, credentialRecordSettings);
        persistAuthenticationState(realm, effectiveUser, credentialRecordSettings,
                authenticationData.getAuthenticatorData().getSignCount(),
                authenticationData.getAuthenticatorData().isFlagBS());
        return effectiveUser;
    }

    private void verifyAuthenticationData(WebAuthnManager webAuthnManager, PublicKeyCredentialRequestOptions options,
            String origin, AuthenticationData authenticationData, WebAuthnDeviceSettings credentialRecordSettings)
            throws WebAuthnCeremonyException {
        try {
            CredentialRecord credentialRecord = credentialMapper.toCredentialRecord(credentialRecordSettings);
            AuthenticationParameters params = authenticationParameters(options, origin, credentialRecord);
            webAuthnManager.verify(authenticationData, params);
        } catch (DataConversionException | VerificationException | IllegalArgumentException | AssertionError e) {
            throw verificationFailure(WebAuthnCeremonyError.ASSERTION_VERIFICATION_FAILED, e);
        }
    }

    private WebAuthnCeremonyException verificationFailure(WebAuthnCeremonyError defaultError, Throwable throwable) {
        if (throwable instanceof BadOriginException || throwable instanceof CrossOriginException) {
            return new WebAuthnCeremonyException(WebAuthnCeremonyError.ORIGIN_MISMATCH, throwable);
        }
        if (throwable instanceof BadRpIdException) {
            return new WebAuthnCeremonyException(WebAuthnCeremonyError.RP_ID_MISMATCH, throwable);
        }
        return new WebAuthnCeremonyException(defaultError, throwable);
    }

    private String resolveUsername(String username, String realm, AuthenticationData authenticationData)
            throws WebAuthnCeremonyException {
        if (username != null && !username.isBlank()) {
            verifyIdentifiedUserHandle(username, realm, authenticationData.getUserHandle());
            return username;
        }
        byte[] userHandle = authenticationData.getUserHandle();
        // WebAuthn Level 3 §7.2 step 6: for discoverable-credential authentication, no user was identified
        // before the ceremony, so response.userHandle must be present and resolve to the credential owner.
        if (userHandle == null || userHandle.length == 0) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.MISSING_USER_HANDLE);
        }
        return accountRepository.findUsernameByUserHandle(userHandle, realm)
                .orElseThrow(() -> new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED));
    }

    private void verifyIdentifiedUserHandle(String username, String realm, byte[] responseUserHandle)
            throws WebAuthnCeremonyException {
        if (responseUserHandle == null || responseUserHandle.length == 0) {
            return;
        }
        // WebAuthn Level 3 §7.2 step 6: when the user was identified before the ceremony, a present
        // response.userHandle must equal that account's user handle.
        if (!Arrays.equals(responseUserHandle, accountRepository.getUserHandle(username, realm))) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_HANDLE_MISMATCH, username, null);
        }
    }

    private WebAuthnDeviceSettings requireCredentialRecord(String realm, String username, byte[] credentialId)
            throws WebAuthnCeremonyException {
        try {
            // WebAuthn Level 3 §7.2 step 7: look up the public key credential source using the response
            // credential ID and the resolved user account.
            return credentialRepository.findCredentialRecord(username, realm, credentialId)
                    // The user handle has been resolved here, but no stored credential has been matched or verified.
                    // Do not attach the username to this failure; the login module must not lock a user from a forged
                    // discoverable-credential response carrying that user's handle and a random credential ID.
                    .orElseThrow(() -> new WebAuthnCeremonyException(
                            WebAuthnCeremonyError.UNKNOWN_CREDENTIAL));
        } catch (IOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.DEVICE_LOOKUP_FAILED, e);
        }
    }

    private void persistAuthenticationState(String realm, String username, WebAuthnDeviceSettings credentialRecord,
            long signatureCount, boolean backupState) throws WebAuthnCeremonyException {
        // §6.1.1 Signature Counter Considerations: a counter that fails to advance signals a cloned authenticator.
        if ((signatureCount > 0 || credentialRecord.getSignCount() > 0)
                && signatureCount <= credentialRecord.getSignCount()) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.ASSERTION_VERIFICATION_FAILED, username, null);
        }
        boolean changed = false;
        if (signatureCount > credentialRecord.getSignCount()) {
            credentialRecord.setSignCount(signatureCount);
            changed = true;
        }
        if (backupState != credentialRecord.isBackupState()) {
            credentialRecord.setBackupState(backupState);
            changed = true;
        }
        if (changed) {
            try {
                credentialRepository.updateCredentialRecord(username, realm, credentialRecord);
            } catch (IOException e) {
                throw new WebAuthnCeremonyException(WebAuthnCeremonyError.COUNTER_PERSIST_FAILED, username, e);
            }
        }
    }

    private RegistrationParameters registrationParameters(PublicKeyCredentialCreationOptions options, String origin) {
        List<PublicKeyCredentialParameters> pubKeyCredParams = options.getPubKeyCredParams().stream()
                .map(param -> new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.create(param.get("alg").asInteger())))
                .collect(Collectors.toList());
        return new RegistrationParameters(serverProperty(origin, options.getRpId(), options.getChallenge()),
                pubKeyCredParams, userVerificationRequired(options.getUserVerification()));
    }

    private AuthenticationParameters authenticationParameters(PublicKeyCredentialRequestOptions options,
            String origin, CredentialRecord credentialRecord) {
        return new AuthenticationParameters(serverProperty(origin, options.getRpId(), options.getChallenge()),
                credentialRecord, allowCredentialIds(options),
                userVerificationRequired(options.getUserVerification()));
    }

    private List<byte[]> allowCredentialIds(PublicKeyCredentialRequestOptions options) {
        List<WebAuthnDeviceSettings> allowCredentials = options.getAllowCredentials();
        if (allowCredentials == null || allowCredentials.isEmpty()) {
            return null;
        }
        // WebAuthn Level 3 §7.2 step 5: if pkOptions.allowCredentials was issued for this ceremony, verify the
        // response credential ID against that original allow-list instead of comparing the response to itself.
        return allowCredentials.stream()
                .map(WebAuthnDeviceSettings::getCredentialId)
                .collect(Collectors.toList());
    }

    private ServerProperty serverProperty(String origin, String rpId, byte[] challengeBytes) {
        Challenge serverChallenge = () -> challengeBytes;
        return new ServerProperty(Origin.create(origin), rpId, serverChallenge);
    }

    private boolean userVerificationRequired(String userVerification) {
        return "required".equals(userVerification);
    }

    private WebAuthnManager newWebAuthnManager() {
        return new WebAuthnManager(statementVerifiers(), new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier());
    }

    private List<AttestationStatementVerifier> statementVerifiers() {
        return Collections.singletonList(new NoneAttestationStatementVerifier());
    }
}
