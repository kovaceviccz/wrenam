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
 * Copyright 2025 Wren Security. All rights reserved.
 */
package org.wrensecurity.wrenam.authentication.modules.webauthn.authentication;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.sm.DNMapper;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.AbstractWebAuthnModule;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnClientResponseException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnClientResponseParser;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnLoginFailureReason;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnPrincipal;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAuthenticationCeremony;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRecoveryCodes;

/**
 * WebAuthn authentication module. A thin JAAS adapter that translates the login state machine and its callbacks
 * to and from the {@link WebAuthnAuthenticationCeremony}; the ceremony owns all WebAuthn logic, and
 * {@link AbstractWebAuthnModule} owns the shared module plumbing.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 &sect;7.2</a>
 */
public class WebAuthnAuthentication extends AbstractWebAuthnModule {

    private final WebAuthnAuthenticationCeremony authenticationCeremony;

    private final WebAuthnRecoveryCodes recoveryCodes;

    private final WebAuthnClientResponseParser clientResponseParser;

    private boolean usernameless;

    private boolean recoveryRequested;

    private String principalName;

    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    private int invalidRecoveryCodeAttempts;

    /**
     * Create a WebAuthn authentication module using configured Guice collaborators.
     */
    public WebAuthnAuthentication() {
        this(InjectorHolder.getInstance(WebAuthnAuthenticationCeremony.class),
                InjectorHolder.getInstance(WebAuthnRecoveryCodes.class),
                InjectorHolder.getInstance(WebAuthnClientResponseParser.class));
    }

    WebAuthnAuthentication(WebAuthnAuthenticationCeremony authenticationCeremony,
            WebAuthnRecoveryCodes recoveryCodes, WebAuthnClientResponseParser clientResponseParser) {
        Reject.ifNull(authenticationCeremony, recoveryCodes, clientResponseParser);
        this.authenticationCeremony = authenticationCeremony;
        this.recoveryCodes = recoveryCodes;
        this.clientResponseParser = clientResponseParser;
    }

    /**
     * Return the authentication module resource name.
     *
     * @return authentication module resource name
     */
    @Override
    protected String resourceName() {
        return Constants.RESOURCE_NAME;
    }

    /**
     * Return whether credential failures should participate in account lockout.
     *
     * @return {@code true} for authentication
     */
    @Override
    protected boolean treatCredentialFailureAsInvalidPassword() {
        return true;
    }

    /**
     * Initialise the WebAuthn authentication module for one authentication attempt.
     *
     * @param subject authenticated subject
     * @param sharedState AM authentication shared state
     * @param options module configuration options
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        this.options = options;
        username = (String) sharedState.get(getUserKey());
        realm = DNMapper.orgNameToRealmName(getRequestOrg());
        if (username != null) {
            user = IdUtils.getIdentity(username, realm);
        }
        usernameless = CollectionHelper.getBooleanMapAttr(options, Constants.USERNAMELESS, false);
        setAuthLevel(CollectionHelper.getIntMapAttr(options, Constants.AUTHENTICATION_LEVEL, 0, debug()));
    }

    /**
     * Drive the authentication state machine.
     *
     * @param callbacks callbacks submitted for the current state
     * @param state current AM authentication state
     * @return next AM authentication state
     * @throws LoginException if authentication cannot continue
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        switch (state) {
            case ISAuthConstants.LOGIN_START:
                return startAuthentication();
            case Constants.STATE_PROMPT_USERNAME:
                return promptUsername(callbacks);
            case Constants.STATE_VALIDATE_SCRIPT_OUTPUT:
                return validateScriptOutput(callbacks);
            case Constants.STATE_RECOVERY_CODE:
                return recoveryCode(callbacks, Constants.RECOVERY_CODE_CALLBACK_INDEX);
            case Constants.STATE_RECOVERY_CODE_USED:
                storeUsername(username);
                principalName = username;
                return ISAuthConstants.LOGIN_SUCCEED;
            case Constants.STATE_RECOVERY_CODE_ERROR:
                return recoveryCode(callbacks, Constants.RECOVERY_CODE_ERROR_CALLBACK_INDEX);
            default:
                throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, null, null);
        }
    }

    /**
     * Return the authenticated WebAuthn principal.
     *
     * @return authenticated principal, or {@code null} before success
     */
    @Override
    public Principal getPrincipal() {
        return principalName == null ? null : new WebAuthnPrincipal(principalName);
    }

    /**
     * Clear module state at the end of the authentication attempt.
     */
    @Override
    public void destroyModuleState() {
        username = null;
        principalName = null;
        recoveryRequested = false;
        invalidRecoveryCodeAttempts = 0;
        nullifyUsedVars();
    }

    /**
     * Clear callback-local state.
     */
    @Override
    public void nullifyUsedVars() {
        super.nullifyUsedVars();
        publicKeyCredentialRequestOptions = null;
    }

    private int startAuthentication() throws AuthLoginException {
        // Start immediately for usernameless OR when user is already known (2FA), otherwise prompt for username.
        if (usernameless || user != null) {
            if (username != null) {
                user = requireActiveUser(username, WebAuthnLoginFailureReason.NOT_ALLOWED);
            }
            publicKeyCredentialRequestOptions = buildRequestOptions(isDiscoverableCredentialFlow());
            replaceScriptCallback(publicKeyCredentialRequestOptions);
            return Constants.STATE_VALIDATE_SCRIPT_OUTPUT;
        }
        return Constants.STATE_PROMPT_USERNAME;
    }

    private int promptUsername(Callback[] callbacks) throws AuthLoginException {
        username = ((NameCallback) callbacks[Constants.STATE_PROMPT_USERNAME_NAME_CALLBACK_INDEX]).getName();
        user = requireActiveUser(username, WebAuthnLoginFailureReason.NOT_ALLOWED);
        if (recoveryRequested) {
            return Constants.STATE_RECOVERY_CODE;
        }
        publicKeyCredentialRequestOptions = buildRequestOptions(false);
        replaceScriptCallback(publicKeyCredentialRequestOptions);
        return Constants.STATE_VALIDATE_SCRIPT_OUTPUT;
    }

    private int validateScriptOutput(Callback[] callbacks) throws AuthLoginException {
        int selectedIndex = ((ConfirmationCallback) callbacks[
                Constants.VALIDATE_SCRIPT_OUTPUT_CONFIRMATION_CALLBACK_INDEX]).getSelectedIndex();
        if (selectedIndex == Constants.VALIDATE_SCRIPT_OUTPUT_RECOVERY_INDEX) {
            recoveryRequested = true;
            if (username == null || username.isBlank()) {
                return Constants.STATE_PROMPT_USERNAME;
            }
            user = requireActiveUser(username, WebAuthnLoginFailureReason.NOT_ALLOWED);
            return Constants.STATE_RECOVERY_CODE;
        }
        String hiddenValueCallbackValue = ((HiddenValueCallback) callbacks[
                Constants.VALIDATE_SCRIPT_OUTPUT_HIDDEN_VALUE_CALLBACK_INDEX]).getValue();
        boolean hasError = selectedIndex == Constants.VALIDATE_SCRIPT_OUTPUT_CANCEL_INDEX;
        String credentialJson;
        try {
            // Keep AM's hidden callback transport out of the WebAuthn ceremony. The ceremony receives only the
            // credential JSON defined by the browser WebAuthn API; client-side failures remain JAAS module concerns.
            credentialJson = clientResponseParser.getCredentialJson(hiddenValueCallbackValue, hasError);
        } catch (WebAuthnClientResponseException e) {
            throw failure(e.reason(), e.getMessage(), null);
        }
        try {
            username = authenticationCeremony.complete(
                    publicKeyCredentialRequestOptions,
                    normalizeOrigin(Constants.RP_ORIGIN),
                    credentialJson,
                    username,
                    realm);
        } catch (WebAuthnCeremonyException e) {
            // In a discoverable-credential flow the response user handle is not proof of account ownership. Do not
            // copy a resolved username from a failed ceremony into module state, because failure() would then set the
            // account failure ID before a valid assertion has established the user.
            throw failure(e);
        }
        // WebAuthn Level 3 Section 7.2 steps 5-6: the resolved user handle must identify an existing, active user.
        user = requireActiveUser(username, WebAuthnLoginFailureReason.CREDENTIAL_NOT_FOUND);
        storeUsername(username);
        principalName = username;
        return ISAuthConstants.LOGIN_SUCCEED;
    }

    private int recoveryCode(Callback[] callbacks, int recoveryCodeCallbackIndex) throws AuthLoginException {
        user = requireActiveUser(username, WebAuthnLoginFailureReason.NOT_ALLOWED);
        String recoveryCode = ((NameCallback) callbacks[recoveryCodeCallbackIndex]).getName();
        if (recoveryCode == null || recoveryCode.isBlank()) {
            return invalidRecoveryCode();
        }
        try {
            if (recoveryCodes.useRecoveryCode(username, realm, recoveryCode)) {
                return Constants.STATE_RECOVERY_CODE_USED;
            }
        } catch (IOException e) {
            throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, "Failed validating recovery code", e);
        }
        return invalidRecoveryCode();
    }

    private int invalidRecoveryCode() throws AuthLoginException {
        invalidRecoveryCodeAttempts += 1;
        if (invalidRecoveryCodeAttempts >= Constants.MAX_RECOVERY_CODE_ATTEMPTS) {
            throw invalidCredentialFailure(WebAuthnLoginFailureReason.VERIFICATION_FAILED,
                    "Invalid recovery code", null);
        }
        return Constants.STATE_RECOVERY_CODE_ERROR;
    }

    private boolean isDiscoverableCredentialFlow() {
        return usernameless && (username == null || username.isBlank());
    }

    private AMIdentity requireActiveUser(String username, WebAuthnLoginFailureReason failureReason)
            throws AuthLoginException {
        if (username == null || username.isBlank()) {
            throw failure(failureReason, null, null);
        }
        try {
            AMIdentity identity = IdUtils.getIdentity(username, realm);
            if (identity == null || !identity.isExists() || !identity.isActive()) {
                throw failure(failureReason, null, null);
            }
            return identity;
        } catch (IdRepoException | SSOException e) {
            throw failure(failureReason, "Failed reading user profile", e);
        }
    }

    private PublicKeyCredentialRequestOptions buildRequestOptions(boolean discoverable) throws AuthLoginException {
        try {
            return authenticationCeremony.initiate(
                    realm,
                    username,
                    CollectionHelper.getMapAttr(options, Constants.RP_ID),
                    CollectionHelper.getIntMapAttr(options, Constants.TIMEOUT, 60000, debug()),
                    CollectionHelper.getMapAttr(options, Constants.USER_VERIFICATION),
                    discoverable);
        } catch (WebAuthnCeremonyException e) {
            throw failure(e);
        }
    }

    private void replaceScriptCallback(PublicKeyCredentialRequestOptions options) throws AuthLoginException {
        String publicKeyJson;
        try {
            publicKeyJson = options.toJson().toString();
        } catch (IOException e) {
            throw new AuthLoginException(Constants.RESOURCE_NAME, "failedPreparingScriptCallback", null, e);
        }
        replaceScriptCallback(
                Constants.STATE_VALIDATE_SCRIPT_OUTPUT,
                Constants.VALIDATE_SCRIPT_OUTPUT_SCRIPT_CALLBACK_INDEX,
                Constants.CREDENTIALS_GET_SCRIPT_TEMPLATE_NAME,
                publicKeyJson);
    }

}
