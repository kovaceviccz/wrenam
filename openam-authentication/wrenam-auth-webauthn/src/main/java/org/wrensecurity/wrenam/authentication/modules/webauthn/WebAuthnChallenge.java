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

import jakarta.inject.Inject;
import java.security.SecureRandom;
import java.time.Clock;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;

/**
 * Generate and validate WebAuthn cryptographic challenges.
 */
public final class WebAuthnChallenge {

    private static final int CHALLENGE_LENGTH_BYTES = 32;

    private final SecureRandom secureRandom;

    private final Clock clock;

    /**
     * Create a challenge service backed by a secure random source and the system clock.
     */
    @Inject
    public WebAuthnChallenge() {
        this(new SecureRandom(), Clock.systemUTC());
    }

    WebAuthnChallenge(SecureRandom secureRandom, Clock clock) {
        Reject.ifNull(secureRandom, clock);
        this.secureRandom = secureRandom;
        this.clock = clock;
    }

    /**
     * Generate a fresh 32-byte cryptographic challenge.
     *
     * @return generated challenge
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">WebAuthn Level 3 &sect;13.4.3</a>
     */
    public byte[] generate() {
        byte[] challenge = new byte[CHALLENGE_LENGTH_BYTES];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    /**
     * Return the current challenge issue timestamp in epoch milliseconds.
     *
     * @return current epoch timestamp
     */
    public long issuedAtMillis() {
        return clock.millis();
    }

    /**
     * Assert that a server-issued challenge has not exceeded its module timeout.
     *
     * @param challengeIssuedAtMillis server-side challenge issue timestamp in epoch milliseconds
     * @param timeoutMillis timeout in milliseconds, or {@code 0} to disable expiry checks
     * @throws WebAuthnCeremonyException if the challenge is expired or has no issue timestamp
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">WebAuthn Level 3 &sect;13.4.3</a>
     */
    public void assertNotExpired(long challengeIssuedAtMillis, int timeoutMillis)
            throws WebAuthnCeremonyException {
        if (timeoutMillis <= 0) {
            return;
        }
        if (challengeIssuedAtMillis <= 0) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.CHALLENGE_EXPIRED);
        }
        long ageMillis = clock.millis() - challengeIssuedAtMillis;
        if (ageMillis > timeoutMillis) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.CHALLENGE_EXPIRED);
        }
    }

}
