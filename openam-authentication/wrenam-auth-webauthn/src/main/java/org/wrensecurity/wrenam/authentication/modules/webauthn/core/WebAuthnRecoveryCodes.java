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

import java.io.IOException;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.openam.utils.CodeException;

/**
 * Manage recovery codes associated with WebAuthn credential records.
 */
public interface WebAuthnRecoveryCodes {

    /**
     * Add freshly generated recovery codes to a credential record.
     *
     * @param credentialRecord credential record to update
     * @throws CodeException if recovery codes cannot be generated
     */
    void addRecoveryCodes(WebAuthnDeviceSettings credentialRecord) throws CodeException;

    /**
     * Consume a matching recovery code for the user.
     *
     * @param username credential owner
     * @param realm realm containing the credential owner
     * @param codeAttempt recovery code entered by the user
     * @return {@code true} when the code was matched and consumed
     * @throws IOException if credential records cannot be updated
     */
    boolean useRecoveryCode(String username, String realm, String codeAttempt) throws IOException;
}
