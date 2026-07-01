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

/**
 * Represent a client-side WebAuthn response failure.
 */
public class WebAuthnClientResponseException extends Exception {

    private final WebAuthnLoginFailureReason reason;

    /**
     * Create a client response failure.
     *
     * @param reason login failure reason
     * @param message safe client-side failure detail, or {@code null}
     */
    public WebAuthnClientResponseException(WebAuthnLoginFailureReason reason, String message) {
        super(message);
        this.reason = reason == null ? WebAuthnLoginFailureReason.VERIFICATION_FAILED : reason;
    }

    /**
     * Return the login failure reason.
     *
     * @return login failure reason
     */
    public WebAuthnLoginFailureReason reason() {
        return reason;
    }

}
