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

import org.forgerock.util.Reject;

/**
 * Represent a WebAuthn ceremony failure raised by the inner layers (ceremony, verifier, repository). It carries a
 * stable {@link WebAuthnCeremonyError} and, when known, the resolved user, but deliberately no i18n bundle: only the
 * login module knows which bundle to localise against, so it maps the code to a user-facing failure at the edge.
 */
public class WebAuthnCeremonyException extends Exception {

    private final WebAuthnCeremonyError error;

    private final String resolvedUsername;

    /**
     * Create a WebAuthn ceremony exception with a stable error code.
     *
     * @param error stable failure code for module-level routing
     */
    public WebAuthnCeremonyException(WebAuthnCeremonyError error) {
        this(error, null, null);
    }

    /**
     * Create a WebAuthn ceremony exception with a stable error code and cause.
     *
     * @param error stable failure code for module-level routing
     * @param cause underlying failure
     */
    public WebAuthnCeremonyException(WebAuthnCeremonyError error, Throwable cause) {
        this(error, null, cause);
    }

    /**
     * Create a WebAuthn ceremony exception with a stable error code, resolved username, and cause.
     *
     * @param error stable failure code for module-level routing
     * @param resolvedUsername account resolved before the failure, or {@code null} if not known
     * @param cause underlying failure
     */
    public WebAuthnCeremonyException(WebAuthnCeremonyError error, String resolvedUsername, Throwable cause) {
        super(error == null ? null : error.code(), cause);
        Reject.ifNull(error);
        this.error = error;
        this.resolvedUsername = resolvedUsername;
    }

    /**
     * Return the stable failure code for module-level routing.
     *
     * @return stable failure code
     */
    public WebAuthnCeremonyError getError() {
        return error;
    }

    /**
     * Return the account resolved from the ceremony before the failure.
     *
     * @return resolved account, or {@code null} if not yet known
     */
    public String getResolvedUsername() {
        return resolvedUsername;
    }
}
