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
package org.wrensecurity.wrenam.authentication.modules.webauthn;

import java.util.Locale;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;

/**
 * WebAuthn login failure reason used for user-facing messaging and failure routing.
 */
public enum WebAuthnLoginFailureReason {

    USER_CANCELLED,

    UNSUPPORTED,

    NO_AUTHENTICATOR,

    ALREADY_REGISTERED,

    NOT_ALLOWED,

    CREDENTIAL_NOT_FOUND,

    NO_REGISTERED_CREDENTIALS,

    CHALLENGE_EXPIRED,

    ORIGIN_MISMATCH,

    RP_ID_MISMATCH,

    VERIFICATION_FAILED;

    /**
     * Return the i18n message key for this failure reason.
     *
     * @return i18n message key
     */
    public String messageKey() {
        return "failureReason." + name();
    }

    /**
     * Resolve a browser-side reason code into a module failure reason.
     *
     * @param reasonCode browser-side reason code
     * @return matching failure reason, or {@link #VERIFICATION_FAILED} for unknown values
     */
    public static WebAuthnLoginFailureReason fromReasonCode(String reasonCode) {
        if (reasonCode == null || reasonCode.isBlank()) {
            return VERIFICATION_FAILED;
        }
        try {
            return WebAuthnLoginFailureReason.valueOf(reasonCode.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return VERIFICATION_FAILED;
        }
    }

    /**
     * Resolve an inner WebAuthn ceremony error into a module failure reason.
     *
     * @param error ceremony, verifier, or repository error
     * @return matching failure reason, or {@link #VERIFICATION_FAILED} for unknown values
     */
    public static WebAuthnLoginFailureReason fromCeremonyError(WebAuthnCeremonyError error) {
        if (error == null) {
            return VERIFICATION_FAILED;
        }
        switch (error) {
            case NO_REGISTERED_CREDENTIALS:
                return NO_REGISTERED_CREDENTIALS;
            case CHALLENGE_EXPIRED:
                return CHALLENGE_EXPIRED;
            case ORIGIN_MISMATCH:
            case MISSING_ORIGIN_CONFIG:
            case INVALID_ORIGIN_CONFIG:
                return ORIGIN_MISMATCH;
            case RP_ID_MISMATCH:
                return RP_ID_MISMATCH;
            case MISSING_USER_HANDLE:
            case USER_HANDLE_MISMATCH:
            case MISSING_CREDENTIAL_ID:
            case UNKNOWN_CREDENTIAL:
            case USER_LOOKUP_FAILED:
            case MISSING_USER_ID_ATTRIBUTE:
                return CREDENTIAL_NOT_FOUND;
            default:
                return VERIFICATION_FAILED;
        }
    }

}
