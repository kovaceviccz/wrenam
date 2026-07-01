/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security.
 */

package org.forgerock.openam.core.rest.server;

import org.forgerock.api.annotations.Title;
import org.forgerock.openam.utils.StringUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * A class to encapsulate a WebAuthn authentication implementation that can be advertised to the login page.
 */
@Title("WebAuthn authentication implementation")
public final class WebAuthnAuthenticationImplementation {

    @Title("Enabled")
    private boolean enabled;

    @Title("Authentication chain")
    private String authnChain;

    public WebAuthnAuthenticationImplementation() {
        this(false, null);
    }

    public WebAuthnAuthenticationImplementation(boolean enabled, String authnChain) {
        this.enabled = enabled;
        this.authnChain = authnChain;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getAuthnChain() {
        return authnChain;
    }

    public void setAuthnChain(String authnChain) {
        this.authnChain = authnChain;
    }

    @JsonIgnore
    public boolean isValid() {
        return enabled && StringUtils.isNotEmpty(authnChain);
    }
}
