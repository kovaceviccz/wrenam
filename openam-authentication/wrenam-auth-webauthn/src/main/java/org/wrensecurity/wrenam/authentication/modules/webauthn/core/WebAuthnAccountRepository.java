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

import java.util.Optional;

/**
 * Resolve WebAuthn account identity data from the local identity store.
 */
public interface WebAuthnAccountRepository {

    /**
     * Get the stable WebAuthn user handle for a local account.
     *
     * @param username local username
     * @param realm realm containing the account
     * @return stable WebAuthn user handle
     * @throws WebAuthnCeremonyException if the account or user handle cannot be resolved
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">WebAuthn Level 3 &sect;14.6.1</a>
     */
    byte[] getUserHandle(String username, String realm) throws WebAuthnCeremonyException;

    /**
     * Get the display name to send in WebAuthn registration options.
     *
     * @param username local username
     * @param realm realm containing the account
     * @return account display name, falling back to {@code username} when no configured display name exists
     * @throws WebAuthnCeremonyException if the account cannot be resolved
     * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity">
     *     WebAuthn Level 3 &sect;5.4.3</a>
     */
    String getDisplayName(String username, String realm) throws WebAuthnCeremonyException;

    /**
     * Find the local username identified by a WebAuthn user handle.
     *
     * @param userHandle WebAuthn user handle from an assertion response
     * @param realm realm to search
     * @return matching username, or empty when no account matches
     * @throws WebAuthnCeremonyException if account lookup fails
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">WebAuthn Level 3 &sect;14.6.1</a>
     */
    Optional<String> findUsernameByUserHandle(byte[] userHandle, String realm) throws WebAuthnCeremonyException;
}
