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

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import java.io.IOException;
import java.util.MissingResourceException;
import java.util.Map;
import java.util.ResourceBundle;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.impl.WebAuthnServiceConfig;

/**
 * Abstract WebAuthn authentication module.
 */
public abstract class AbstractWebAuthnModule extends AMLoginModule {

    private final WebAuthnServiceConfig webAuthnServiceConfig;

    private final WebAuthnBrowserScriptRenderer scriptRenderer;

    protected Map options;

    protected String username;

    protected String realm;

    protected AMIdentity user;

    private Debug debug;

    /**
     * Create shared WebAuthn module plumbing using configured Guice collaborators.
     */
    protected AbstractWebAuthnModule() {
        this(InjectorHolder.getInstance(WebAuthnServiceConfig.class),
                InjectorHolder.getInstance(WebAuthnBrowserScriptRenderer.class));
    }

    AbstractWebAuthnModule(WebAuthnServiceConfig webAuthnServiceConfig,
            WebAuthnBrowserScriptRenderer scriptRenderer) {
        Reject.ifNull(webAuthnServiceConfig, scriptRenderer);
        this.webAuthnServiceConfig = webAuthnServiceConfig;
        this.scriptRenderer = scriptRenderer;
    }

    /**
     * Return the module's i18n bundle resource name, e.g. {@code amAuthWebAuthnAuthentication}.
     *
     * @return module resource name
     */
    protected abstract String resourceName();

    /**
     * Return whether credential-style failures should surface as {@link InvalidPasswordException} so account lockout
     * handling engages.
     *
     * @return {@code true} when credential failures should be invalid password failures
     */
    protected boolean treatCredentialFailureAsInvalidPassword() {
        return false;
    }

    /**
     * Return the module debug logger.
     *
     * @return module debug logger
     */
    protected Debug debug() {
        if (debug == null) {
            debug = Debug.getInstance(resourceName());
        }
        return debug;
    }

    /**
     * Resolve a message from this module's resource bundle, falling back to a stable English default when the key is
     * unavailable. The fallback keeps callback setup deterministic while still allowing normal AM bundle overrides.
     *
     * @param key resource bundle key
     * @param fallback fallback value
     * @return localized message or fallback
     */
    protected String message(String key, String fallback) {
        try {
            ResourceBundle bundle = amCache.getResBundle(resourceName(), getLoginLocale());
            if (bundle != null && bundle.containsKey(key)) {
                return bundle.getString(key);
            }
        } catch (MissingResourceException e) {
            debug().message("Missing WebAuthn resource bundle key: " + key);
        }
        return fallback;
    }

    /**
     * Read the configured relying party origin from the module options and normalise it.
     *
     * @param originConfigKey module configuration key containing the relying party origin
     * @return normalised relying party origin
     * @throws AuthLoginException if the configured origin is missing or invalid
     */
    protected String normalizeOrigin(String originConfigKey) throws AuthLoginException {
        try {
            String configuredOrigin = CollectionHelper.getMapAttr(options, originConfigKey);
            return webAuthnServiceConfig.normalizeConfiguredOrigin(configuredOrigin);
        } catch (WebAuthnCeremonyException e) {
            throw failure(e);
        }
    }

    /**
     * Build the login exception for a ceremony failure.
     *
     * @param e ceremony failure
     * @return login exception for the authentication chain
     */
    protected AuthLoginException failure(WebAuthnCeremonyException e) {
        boolean invalidCredentialFailure = isInvalidCredentialFailure(e.getError());
        return failure(WebAuthnLoginFailureReason.fromCeremonyError(e.getError()), e.getError().code(), e,
                invalidCredentialFailure, invalidCredentialFailure ? e.getResolvedUsername() : null);
    }

    /**
     * Log a WebAuthn failure, flag the failed user, and build the matching exception for the chain.
     *
     * @param reason module failure reason
     * @param detail stable internal detail, or {@code null}
     * @param cause underlying failure, or {@code null}
     * @return login exception for the authentication chain
     */
    protected AuthLoginException failure(WebAuthnLoginFailureReason reason, String detail, Throwable cause) {
        return failure(reason, detail, cause, false, null);
    }

    /**
     * Build a failure that represents an invalid credential value and should engage AM's invalid-password handling.
     *
     * @param reason module failure reason
     * @param detail stable internal detail, or {@code null}
     * @param cause underlying failure, or {@code null}
     * @return login exception for the authentication chain
     */
    protected AuthLoginException invalidCredentialFailure(WebAuthnLoginFailureReason reason, String detail,
            Throwable cause) {
        return failure(reason, detail, cause, true, null);
    }

    private AuthLoginException failure(WebAuthnLoginFailureReason reason, String detail, Throwable cause,
            boolean invalidCredentialFailure, String resolvedUsername) {
        String failureUsername = failureUsername(resolvedUsername);
        if (failureUsername != null) {
            setFailureID(failureUsername);
        }
        StringBuilder logLine = new StringBuilder("WebAuthn failure; module=").append(resourceName())
                .append(", reason=").append(reason.name()).append(", realm=").append(realm);
        if (failureUsername != null) {
            logLine.append(", user=").append(failureUsername);
        }
        if (detail != null && !detail.isBlank()) {
            logLine.append(", detail=").append(detail);
        }
        if (cause != null) {
            debug().warning(logLine.toString(), cause);
        } else {
            debug().warning(logLine.toString());
        }
        if (treatCredentialFailureAsInvalidPassword() && invalidCredentialFailure
                && failureUsername != null) {
            return new InvalidPasswordException(resourceName(), reason.messageKey(), null, failureUsername, cause);
        }
        return new AuthLoginException(resourceName(), reason.messageKey(), null, cause);
    }

    private String failureUsername(String resolvedUsername) {
        if (username != null && !username.isBlank()) {
            return username;
        }
        if (resolvedUsername != null && !resolvedUsername.isBlank()) {
            return resolvedUsername;
        }
        return null;
    }

    private boolean isInvalidCredentialFailure(WebAuthnCeremonyError error) {
        switch (error) {
            case UNKNOWN_CREDENTIAL:
            case ASSERTION_VERIFICATION_FAILED:
                return true;
            default:
                return false;
        }
    }

    /**
     * Render the browser-side WebAuthn script callback and install it at the given state/index. The options JSON
     * is base64url-encoded into the template; the encoding is the injection defence, since the browser script only
     * decodes a bounded base64url blob and the options can therefore never break out of the script string.
     *
     * @param state module state containing the callback
     * @param callbackIndex callback index to replace
     * @param templateResourceName browser script template resource
     * @param publicKeyJson public key options JSON
     * @throws AuthLoginException if the script callback cannot be prepared
     */
    protected void replaceScriptCallback(int state, int callbackIndex, String templateResourceName,
            String publicKeyJson) throws AuthLoginException {
        try {
            replaceCallback(state, callbackIndex,
                    scriptRenderer.render(getClass().getClassLoader(), templateResourceName, publicKeyJson));
        } catch (IOException e) {
            throw new AuthLoginException(resourceName(), "failedPreparingScriptCallback", null, e);
        }
    }

    /**
     * Clear state held between callbacks.
     */
    @Override
    public void nullifyUsedVars() {
        options = null;
        realm = null;
        user = null;
    }

}
