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
package org.wrensecurity.wrenam.authentication.modules.webauthn.registration;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.DateUtils;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.sm.DNMapper;
import java.io.IOException;
import java.security.Principal;
import java.text.ParseException;
import java.time.Clock;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.login.LoginException;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.util.Reject;
import org.wrensecurity.wrenam.authentication.modules.webauthn.AbstractWebAuthnModule;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnClientResponseException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnClientResponseParser;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnLoginFailureReason;
import org.wrensecurity.wrenam.authentication.modules.webauthn.WebAuthnPrincipal;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnRegistrationCeremony;

/**
 * WebAuthn registration module that lets users authenticated earlier in the chain register a device.
 */
public class WebAuthnRegistration extends AbstractWebAuthnModule {

    private static final String EMPTY_SELECTION = "[Empty]";

    private static final String PASSKEY_NAME_PROMPT_KEY = "passkeyNamePrompt";

    private static final String PASSKEY_NAME_PROMPT = "Passkey name";

    private static final String PASSKEY_NAME_DEFAULT_KEY = "passkeyNameDefault";

    private static final String PASSKEY_NAME_DEFAULT = "Passkey";

    private final WebAuthnRegistrationCeremony registrationCeremony;

    private final WebAuthnClientResponseParser clientResponseParser;

    private final Clock clock;

    private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

    private WebAuthnDeviceSettings credentialRecord;

    private int maxAuthAgeMillis;

    /**
     * Create a WebAuthn registration module using configured Guice collaborators.
     */
    public WebAuthnRegistration() {
        this(InjectorHolder.getInstance(WebAuthnRegistrationCeremony.class),
                InjectorHolder.getInstance(WebAuthnClientResponseParser.class),
                Clock.systemUTC());
    }

    WebAuthnRegistration(WebAuthnRegistrationCeremony registrationCeremony,
            WebAuthnClientResponseParser clientResponseParser, Clock clock) {
        Reject.ifNull(registrationCeremony, clientResponseParser, clock);
        this.registrationCeremony = registrationCeremony;
        this.clientResponseParser = clientResponseParser;
        this.clock = clock;
    }

    /**
     * Return the registration module resource name.
     *
     * @return registration module resource name
     */
    @Override
    protected String resourceName() {
        return RegistrationConstants.RESOURCE_NAME;
    }

    /**
     * Initialise the WebAuthn registration module for one registration attempt.
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
        user = IdUtils.getIdentity(username, realm);
        maxAuthAgeMillis = CollectionHelper.getIntMapAttr(
                options, RegistrationConstants.MAX_AUTH_AGE, 300000, debug());
        setAuthLevel(CollectionHelper.getIntMapAttr(options, RegistrationConstants.AUTHENTICATION_LEVEL, 0, debug()));
    }

    /**
     * Drive the registration state machine.
     *
     * @param callbacks callbacks submitted for the current state
     * @param state current AM authentication state
     * @return next AM authentication state
     * @throws LoginException if registration cannot continue
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        if (user == null) {
            throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, "Registration requires authenticated user", null);
        }
        if (state != RegistrationConstants.STATE_SHOW_RECOVERY_CODES) {
            enforceRecentAuthentication();
        }

        switch (state) {
            case ISAuthConstants.LOGIN_START:
                return startRegistration();
            case RegistrationConstants.STATE_VALIDATE_SCRIPT_OUTPUT:
                return validateScriptOutput(callbacks);
            case RegistrationConstants.STATE_COMPLETE_REGISTRATION:
                return completeRegistration(callbacks);
            case RegistrationConstants.STATE_SHOW_RECOVERY_CODES:
                // The codes were revealed once on the previous screen; acknowledging simply finishes the chain.
                return ISAuthConstants.LOGIN_SUCCEED;
            default:
                throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, null, null);
        }
    }

    /**
     * Return the registering WebAuthn principal.
     *
     * @return registering principal, or {@code null} before the user is known
     */
    @Override
    public Principal getPrincipal() {
        return username == null ? null : new WebAuthnPrincipal(username);
    }

    /**
     * Clear module state at the end of the registration attempt.
     */
    @Override
    public void destroyModuleState() {
        username = null;
        nullifyUsedVars();
    }

    /**
     * Clear callback-local state.
     */
    @Override
    public void nullifyUsedVars() {
        super.nullifyUsedVars();
        publicKeyCredentialCreationOptions = null;
        credentialRecord = null;
    }

    private int startRegistration() throws AuthLoginException {
        // WebAuthn Level 3 Section 7.1 step 1: build creation options for navigator.credentials.create().
        publicKeyCredentialCreationOptions = buildCreationOptions();
        replaceScriptCallback(publicKeyCredentialCreationOptions);
        return RegistrationConstants.STATE_VALIDATE_SCRIPT_OUTPUT;
    }

    private int validateScriptOutput(Callback[] callbacks) throws AuthLoginException {
        String hiddenValueCallbackValue = ((HiddenValueCallback) callbacks[
                RegistrationConstants.VALIDATE_SCRIPT_OUTPUT_HIDDEN_VALUE_CALLBACK_INDEX]).getValue();
        boolean hasError = ((ConfirmationCallback) callbacks[
                RegistrationConstants.VALIDATE_SCRIPT_OUTPUT_CONFIRMATION_CALLBACK_INDEX]).getSelectedIndex() == 1;
        String credentialJson;
        try {
            // Keep AM's hidden callback transport out of the WebAuthn ceremony. The ceremony receives only the
            // credential JSON defined by the browser WebAuthn API; client-side failures remain JAAS module concerns.
            credentialJson = clientResponseParser.getCredentialJson(hiddenValueCallbackValue, hasError);
        } catch (WebAuthnClientResponseException e) {
            throw failure(e.reason(), e.getMessage(), null);
        }
        final String origin = normalizeOrigin(RegistrationConstants.RP_ORIGIN);
        try {
            credentialRecord = registrationCeremony.verify(
                    publicKeyCredentialCreationOptions,
                    origin,
                    credentialJson);
        } catch (WebAuthnCeremonyException e) {
            throw failure(e);
        }
        preparePasskeyNameCallback();
        return RegistrationConstants.STATE_COMPLETE_REGISTRATION;
    }

    private int completeRegistration(Callback[] callbacks) throws AuthLoginException {
        if (credentialRecord == null) {
            throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED,
                    "Registration credential record missing", null);
        }
        boolean renameRequested = ((ConfirmationCallback) callbacks[
                RegistrationConstants.COMPLETE_REGISTRATION_CONFIRMATION_CALLBACK_INDEX]).getSelectedIndex() == 0;
        if (renameRequested) {
            String friendlyName = ((NameCallback) callbacks[
                    RegistrationConstants.COMPLETE_REGISTRATION_NAME_CALLBACK_INDEX]).getName();
            if (friendlyName != null && !friendlyName.isBlank()) {
                try {
                    credentialRecord.setDeviceName(WebAuthnDeviceSettings.validateDeviceName(friendlyName));
                } catch (IllegalArgumentException e) {
                    throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, e.getMessage(), e);
                }
            }
        }
        credentialRecord.setRpId(publicKeyCredentialCreationOptions.getRpId());
        credentialRecord.setUserId(publicKeyCredentialCreationOptions.getUserId());
        String[] recoveryCodes;
        try {
            recoveryCodes = registrationCeremony.finalizeRegistration(username, realm, credentialRecord);
        } catch (WebAuthnCeremonyException e) {
            throw failure(e);
        }
        // One-time reveal: surface the freshly generated plaintext codes to the user before completing.
        presentRecoveryCodes(recoveryCodes);
        return RegistrationConstants.STATE_SHOW_RECOVERY_CODES;
    }

    private void presentRecoveryCodes(String[] recoveryCodes) throws AuthLoginException {
        String message = recoveryCodes == null ? "" : String.join("\n", recoveryCodes);
        replaceCallback(
                RegistrationConstants.STATE_SHOW_RECOVERY_CODES,
                RegistrationConstants.SHOW_RECOVERY_CODES_TEXT_OUTPUT_CALLBACK_INDEX,
                new TextOutputCallback(TextOutputCallback.INFORMATION, message));
    }

    private void preparePasskeyNameCallback() throws AuthLoginException {
        String prompt = message(PASSKEY_NAME_PROMPT_KEY, PASSKEY_NAME_PROMPT);
        String defaultName = message(PASSKEY_NAME_DEFAULT_KEY, PASSKEY_NAME_DEFAULT);
        replaceCallback(RegistrationConstants.STATE_COMPLETE_REGISTRATION,
                RegistrationConstants.COMPLETE_REGISTRATION_NAME_CALLBACK_INDEX,
                new NameCallback(prompt, defaultName));
    }

    private PublicKeyCredentialCreationOptions buildCreationOptions() throws AuthLoginException {
        String authenticatorAttachment = CollectionHelper.getMapAttr(options,
                RegistrationConstants.AUTHENTICATOR_ATTACHMENT);
        try {
            return registrationCeremony.initiate(
                    realm,
                    username,
                    CollectionHelper.getMapAttr(options, RegistrationConstants.RP_ID),
                    CollectionHelper.getMapAttr(options, RegistrationConstants.RP_NAME),
                    CollectionHelper.getIntMapAttr(options, RegistrationConstants.TIMEOUT, 60000, debug()),
                    CollectionHelper.getMapAttr(options, RegistrationConstants.USER_VERIFICATION),
                    EMPTY_SELECTION.equals(authenticatorAttachment) ? null : authenticatorAttachment,
                    CollectionHelper.getMapAttr(options, RegistrationConstants.RESIDENT_KEY));
        } catch (WebAuthnCeremonyException e) {
            throw failure(e);
        }
    }

    private void replaceScriptCallback(PublicKeyCredentialCreationOptions options) throws AuthLoginException {
        String publicKeyJson;
        try {
            publicKeyJson = options.toJson().toString();
        } catch (IOException e) {
            throw new AuthLoginException(RegistrationConstants.RESOURCE_NAME, "failedPreparingScriptCallback", null, e);
        }
        replaceScriptCallback(
                RegistrationConstants.STATE_VALIDATE_SCRIPT_OUTPUT,
                RegistrationConstants.VALIDATE_SCRIPT_OUTPUT_SCRIPT_CALLBACK_INDEX,
                RegistrationConstants.CREDENTIALS_CREATE_SCRIPT_TEMPLATE_NAME,
                publicKeyJson);
    }

    private void enforceRecentAuthentication() throws AuthLoginException {
        if (maxAuthAgeMillis <= 0) {
            return;
        }
        String authInstant = getUserSessionProperty(ISAuthConstants.AUTH_INSTANT);
        if (authInstant == null || authInstant.isBlank()) {
            throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, "Recent authentication required", null);
        }
        try {
            long age = clock.millis() - DateUtils.stringToDate(authInstant).getTime();
            if (age > maxAuthAgeMillis) {
                throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, "Recent authentication required", null);
            }
        } catch (ParseException e) {
            throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, "Recent authentication required", e);
        }
    }

}
