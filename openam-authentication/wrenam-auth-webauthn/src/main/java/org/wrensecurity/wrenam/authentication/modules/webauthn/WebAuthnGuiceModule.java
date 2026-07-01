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

import com.google.inject.AbstractModule;
import org.forgerock.guice.core.GuiceModule;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAccountRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAuthenticationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCredentialVerifier;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRecoveryCodes;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRegistrationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.AmWebAuthnAccountRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.AmWebAuthnAuthenticationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.AmWebAuthnCredentialRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.AmWebAuthnRecoveryCodes;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.AmWebAuthnRegistrationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.webauthn4j.WebAuthn4JCredentialVerifier;

/**
 * Configure the guice framework for the WebAuthn authentication module.
 */
@GuiceModule
public class WebAuthnGuiceModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(WebAuthnAccountRepository.class).to(AmWebAuthnAccountRepository.class);
        bind(WebAuthnCredentialRepository.class).to(AmWebAuthnCredentialRepository.class);
        bind(WebAuthnRecoveryCodes.class).to(AmWebAuthnRecoveryCodes.class);
        bind(WebAuthnCredentialVerifier.class).to(WebAuthn4JCredentialVerifier.class);
        bind(WebAuthnAuthenticationCeremony.class).to(AmWebAuthnAuthenticationCeremony.class);
        bind(WebAuthnRegistrationCeremony.class).to(AmWebAuthnRegistrationCeremony.class);
    }

}
