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

/**
 * Identify stable WebAuthn ceremony failures used for logging, routing, and i18n message lookup.
 */
public enum WebAuthnCeremonyError {

    NO_REGISTERED_CREDENTIALS("noRegisteredCredentials"),

    CHALLENGE_EXPIRED("challengeExpired"),

    ORIGIN_MISMATCH("originMismatch"),

    MISSING_ORIGIN_CONFIG("missingOriginConfig"),

    INVALID_ORIGIN_CONFIG("invalidOriginConfig"),

    RP_ID_MISMATCH("rpIdMismatch"),

    MISSING_USER_HANDLE("missingUserHandle"),

    USER_HANDLE_MISMATCH("userHandleMismatch"),

    MISSING_CREDENTIAL_ID("missingCredentialId"),

    UNKNOWN_CREDENTIAL("unknownCredential"),

    USER_LOOKUP_FAILED("userLookupFailed"),

    MISSING_USER_ID_ATTRIBUTE("missingUserIdAttribute"),

    WEBAUTHN_SERVICE_CONFIG_ERROR("webauthnServiceConfigError"),

    USER_ID_ATTR_LOOKUP_FAILED("userIdAttrLookupFailed"),

    FAILED_PREPARING_REQUEST_OPTIONS("failedPreparingRequestOptions"),

    FAILED_BUILDING_REGISTRATION_OPTIONS("failedBuildingRegistrationOptions"),

    REGISTRATION_PARSE_FAILED("registrationParseFailed"),

    ASSERTION_PARSE_FAILED("assertionParseFailed"),

    REGISTRATION_VERIFICATION_FAILED("registrationVerificationFailed"),

    ASSERTION_VERIFICATION_FAILED("assertionVerificationFailed"),

    DEVICE_LOOKUP_FAILED("deviceLookupFailed"),

    COUNTER_PERSIST_FAILED("counterPersistFailed"),

    RECOVERY_CODE_GENERATION_FAILED("recoveryCodeGenerationFailed"),

    CREDENTIAL_PERSIST_FAILED("credentialPersistFailed");

    private final String code;

    WebAuthnCeremonyError(String code) {
        this.code = code;
    }

    /**
     * Return the stable error code used in logs and resource bundles.
     *
     * @return stable error code
     */
    public String code() {
        return code;
    }
}
