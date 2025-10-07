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
package org.wrensecurity.wrenam.authentication.modules.webauthn;

import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.AUTHENTICATION_LEVEL;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.CREDENTIALS_GET_SCRIPT_TEMPLATE_NAME;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.RESOURCE_NAME;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.RP_ID;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.STATE_PROMPT_USERNAME;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.STATE_PROMPT_USERNAME_NAME_CALLBACK_INDEX;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.STATE_VALIDATE_SCRIPT_OUTPUT;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.TIMEOUT;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.USERNAMELESS;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.USER_VERIFICATION;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.RP_ORIGIN;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.VALIDATE_SCRIPT_OUTPUT_CONFIRMATION_CALLBACK_INDEX;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.VALIDATE_SCRIPT_OUTPUT_HIDDEN_VALUE_CALLBACK_INDEX;
import static org.wrensecurity.wrenam.authentication.modules.webauthn.Constants.VALIDATE_SCRIPT_OUTPUT_SCRIPT_CALLBACK_INDEX;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;

import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.openam.utils.IOUtils;

/**
 * WebAuthn authentication module.
 */
public class WebAuthn extends AMLoginModule {

    private static final Debug debug = Debug.getInstance(RESOURCE_NAME);

    protected final WebAuthnDeviceProfileManager webAuthnDeviceProfileManager =
            InjectorHolder.getInstance(WebAuthnDeviceProfileManager.class);

    private final WebAuthnChallengeProvider challengeProvider =
            InjectorHolder.getInstance(WebAuthnChallengeProvider.class);

    private final WebAuthnResponseHandler webAuthnResponseHandler = new WebAuthnResponseHandler();

    private Map options;

    private String username;

    private String realm;

    private AMIdentity user;

    private boolean usernameless;

    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        this.options = options;
        this.username = (String) sharedState.get(getUserKey());
        this.realm = DNMapper.orgNameToRealmName(getRequestOrg());
        if (username != null) {
            this.user = IdUtils.getIdentity(username, realm);
        }
        this.usernameless = CollectionHelper.getBooleanMapAttr(options, USERNAMELESS, false);
        setAuthLevel(CollectionHelper.getIntMapAttr(options, AUTHENTICATION_LEVEL, 0, debug));
    }

    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        switch (state) {
        case ISAuthConstants.LOGIN_START:
            return startAuthentication();
        case STATE_PROMPT_USERNAME:
            return promptUsername(callbacks);
        case STATE_VALIDATE_SCRIPT_OUTPUT:
            return validateScriptOutput(callbacks);
        default:
            throw new AuthLoginException("Invalid state");
        }
    }

    @Override
    public Principal getPrincipal() {
        return new WebAuthnPrincipal(username);
    }

    private int startAuthentication() throws AuthLoginException {
        // Start immediately for usernameless OR when user is already known (2FA), otherwise prompt for username
        if (usernameless || user != null) {
            publicKeyCredentialRequestOptions = preparePublicKeyCredentialRequestOptions(usernameless);
            ScriptTextOutputCallback scriptCallback = prepareScriptCallback(publicKeyCredentialRequestOptions);
            replaceCallback(STATE_VALIDATE_SCRIPT_OUTPUT, VALIDATE_SCRIPT_OUTPUT_SCRIPT_CALLBACK_INDEX, scriptCallback);
            return STATE_VALIDATE_SCRIPT_OUTPUT;
        }
        return STATE_PROMPT_USERNAME;
    }

    private int promptUsername(Callback[] callbacks) throws AuthLoginException {
        username = ((NameCallback) callbacks[STATE_PROMPT_USERNAME_NAME_CALLBACK_INDEX]).getName();
        if (username != null) {
            user = IdUtils.getIdentity(username, realm);
        }
        publicKeyCredentialRequestOptions = preparePublicKeyCredentialRequestOptions(false);
        ScriptTextOutputCallback scriptCallback = prepareScriptCallback(publicKeyCredentialRequestOptions);
        replaceCallback(STATE_VALIDATE_SCRIPT_OUTPUT, VALIDATE_SCRIPT_OUTPUT_SCRIPT_CALLBACK_INDEX, scriptCallback);
        return STATE_VALIDATE_SCRIPT_OUTPUT;
    }

    private int validateScriptOutput(Callback[] callbacks) throws AuthLoginException {
        String hiddenValueCallbackValue =
                ((HiddenValueCallback) callbacks[VALIDATE_SCRIPT_OUTPUT_HIDDEN_VALUE_CALLBACK_INDEX]).getValue();
        boolean hasError = ((ConfirmationCallback) callbacks[VALIDATE_SCRIPT_OUTPUT_CONFIRMATION_CALLBACK_INDEX])
                .getSelectedIndex() == 1;
        if (hasError) {
            throw new AuthLoginException(RESOURCE_NAME, "authenticatorError", null);
        }
        String resolvedUsername = webAuthnResponseHandler.handleAuthenticationResponse(
                        publicKeyCredentialRequestOptions, hiddenValueCallbackValue, username, realm);
        if (resolvedUsername != null) {
            username = resolvedUsername;
            user = IdUtils.getIdentity(username, realm);
            if (user == null) {
                // userHandle present but not mapped to a directory entry
                throw new AuthLoginException(RESOURCE_NAME, "userLookupFailed", null);
            }
        }
        if (usernameless && user == null) {
            throw new AuthLoginException(RESOURCE_NAME, "missingUserHandle", null);
        }
        return ISAuthConstants.LOGIN_SUCCEED;
    }

    private PublicKeyCredentialRequestOptions preparePublicKeyCredentialRequestOptions(boolean usernameless)
            throws AuthLoginException {
        try {
            PublicKeyCredentialRequestOptions.Builder builder =
                    new PublicKeyCredentialRequestOptions.Builder()
                            .challenge(challengeProvider.generateChallenge())
                            .rpId(CollectionHelper.getMapAttr(options, RP_ID))
                            .origin(CollectionHelper.getMapAttr(options, RP_ORIGIN))
                            .timeout(CollectionHelper.getIntMapAttr(options, TIMEOUT, 60000, debug))
                            .userVerification(CollectionHelper.getMapAttr(options, USER_VERIFICATION));
            if (!usernameless) {
                List<WebAuthnDeviceSettings> allowCredentials =
                        webAuthnDeviceProfileManager.getDeviceProfiles(username, realm);
                builder.allowCredentials(allowCredentials);
            }
            return builder.build();
        } catch (IOException e) {
            throw new AuthLoginException(RESOURCE_NAME, "failedPreparingPublicKeyCredentialRequestOptions", null, e);
        }
    }

    private ScriptTextOutputCallback prepareScriptCallback(
            PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions) throws AuthLoginException {
        String script;
        try {
            String scriptTemplate = IOUtils.readStream(
                    getClass().getClassLoader().getResourceAsStream(CREDENTIALS_GET_SCRIPT_TEMPLATE_NAME));
            String publicKey = publicKeyCredentialRequestOptions.toJson().toString();
            script = scriptTemplate.replace("{publicKey}", publicKey);
        } catch (IOException e) {
            throw new AuthLoginException(RESOURCE_NAME, "failedPreparingScriptCallback", null, e);
        }
        return new ScriptTextOutputCallback(script);
    }

}
