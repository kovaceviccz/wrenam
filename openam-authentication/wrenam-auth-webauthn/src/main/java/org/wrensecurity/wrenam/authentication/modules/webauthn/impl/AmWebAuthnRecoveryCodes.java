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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.openam.utils.Alphabet;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRecoveryCodes;

/**
 * AM-backed recovery code manager stored on individual WebAuthn credential records.
 */
public class AmWebAuthnRecoveryCodes implements WebAuthnRecoveryCodes {

    static final int NUM_RECOVERY_CODES = 10;

    private final WebAuthnCredentialRepository credentialRepository;

    private final RecoveryCodeGenerator recoveryCodeGenerator;

    /**
     * Create an AM-backed WebAuthn recovery code manager.
     *
     * @param credentialRepository credential repository
     * @param recoveryCodeGenerator recovery code generator
     */
    @Inject
    public AmWebAuthnRecoveryCodes(WebAuthnCredentialRepository credentialRepository,
            RecoveryCodeGenerator recoveryCodeGenerator) {
        Reject.ifNull(credentialRepository, recoveryCodeGenerator);
        this.credentialRepository = credentialRepository;
        this.recoveryCodeGenerator = recoveryCodeGenerator;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addRecoveryCodes(WebAuthnDeviceSettings credentialRecord) throws CodeException {
        Reject.ifNull(credentialRecord);
        credentialRecord.setRecoveryCodes(
                recoveryCodeGenerator.generateCodes(NUM_RECOVERY_CODES, Alphabet.ALPHANUMERIC, false));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean useRecoveryCode(String username, String realm, String codeAttempt) throws IOException {
        Reject.ifNull(username, realm, codeAttempt);
        for (WebAuthnDeviceSettings credentialRecord : credentialRepository.getCredentialRecords(username, realm)) {
            String[] storedRecoveryCodes = credentialRecord.getRecoveryCodes();
            if (storedRecoveryCodes == null || storedRecoveryCodes.length == 0) {
                continue;
            }
            List<String> recoveryCodes = new ArrayList<>(Arrays.asList(storedRecoveryCodes));
            if (recoveryCodes.contains(codeAttempt)) {
                recoveryCodes.remove(codeAttempt);
                credentialRecord.setRecoveryCodes(recoveryCodes.toArray(new String[0]));
                credentialRepository.updateCredentialRecord(username, realm, credentialRecord);
                return true;
            }
        }
        return false;
    }
}
