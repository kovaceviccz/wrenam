(function () {
    const STATUS_OK = "ok";
    const STATUS_ERROR = "error";
    const REASON_VERIFICATION_FAILED = "VERIFICATION_FAILED";
    const REASON_USER_CANCELLED = "USER_CANCELLED";
    const REASON_NOT_ALLOWED = "NOT_ALLOWED";
    const REASON_NO_AUTHENTICATOR = "NO_AUTHENTICATOR";
    const REASON_UNSUPPORTED = "UNSUPPORTED";
    const REASON_ALREADY_REGISTERED = "ALREADY_REGISTERED";
    const REASON_ORIGIN_MISMATCH = "ORIGIN_MISMATCH";
    const CODE_CONSTRAINT = "CONSTRAINT";
    const CODE_INVALID_STATE = "INVALID_STATE";
    const CODE_INVALID_REQUEST = "INVALID_REQUEST";
    const CODE_PARSE_OPTIONS_FAILED = "PARSE_OPTIONS_FAILED";
    const CODE_JSON_PARSING_UNSUPPORTED = "JSON_PARSING_UNSUPPORTED";
    const CODE_JSON_SERIALIZATION_UNSUPPORTED = "JSON_SERIALIZATION_UNSUPPORTED";
    const CODE_TIMEOUT = "TIMEOUT";
    const OPTIONS_B64 = "{publicKeyB64}";
    const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
    const MAX_OPTIONS_JSON_LENGTH = 65536;

    const output = document.getElementById("clientScriptOutputData");
    const successButton = document.getElementById("button_1");
    const errorButton = document.getElementById("button_2");
    const passkeyPanel = document.getElementById("passkey-authn-panel");
    const passkeyHeadingText = passkeyPanel ? passkeyPanel.querySelector("[data-passkey-heading-text]") : null;
    const passkeyHelp = passkeyPanel ? passkeyPanel.querySelector("[data-passkey-help]") : null;
    const retryButton = passkeyPanel ? passkeyPanel.querySelector("[data-passkey-try-again]") : null;
    const waitingPanel = passkeyPanel ? passkeyPanel.querySelector("[data-passkey-waiting]") : null;
    const secondaryActions = document.querySelector("[data-passkey-secondary-actions]");

    if (!output || !successButton || !errorButton) {
        return;
    }

    const textFromAttribute = function (attributeName) {
        return (passkeyPanel && passkeyPanel.getAttribute(attributeName)) || "";
    };

    const clientFailure = function (reason, code) {
        return {
            reason: reason,
            code: code || reason,
        };
    };

    // AM gives the browser script one HiddenValueCallback. Submit one bounded JSON document:
    // success carries credential.toJSON(); user cancellation is submitted as status:error.
    const base64UrlToUtf8 = function (base64Url) {
        if (typeof base64Url !== "string" || base64Url.length === 0
                || base64Url.length > MAX_OPTIONS_JSON_LENGTH * 2 || !BASE64URL_RE.test(base64Url)) {
            throw new Error("INVALID_OPTIONS_PAYLOAD");
        }
        const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
        const paddedBase64 = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
        const binary = atob(paddedBase64);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (decoded.length > MAX_OPTIONS_JSON_LENGTH) {
            throw new Error("OPTIONS_PAYLOAD_TOO_LARGE");
        }
        return decoded;
    };

    const credentialToJSON = function (credential) {
        if (!credential || typeof credential.toJSON !== "function") {
            throw new Error("CREDENTIAL_JSON_UNSUPPORTED");
        }
        return credential.toJSON();
    };

    const toFailure = function (error) {
        if (!error) {
            return clientFailure(REASON_VERIFICATION_FAILED, CODE_INVALID_REQUEST);
        }
        switch (error.name) {
        case "AbortError":
            return clientFailure(REASON_USER_CANCELLED);
        case "NotAllowedError":
            return clientFailure(REASON_NOT_ALLOWED);
        case "NotFoundError":
            return clientFailure(REASON_NO_AUTHENTICATOR);
        case "NotSupportedError":
            return clientFailure(REASON_UNSUPPORTED);
        case "SecurityError":
            return clientFailure(REASON_ORIGIN_MISMATCH);
        case "ConstraintError":
            return clientFailure(REASON_NO_AUTHENTICATOR, CODE_CONSTRAINT);
        case "InvalidStateError":
            return clientFailure(REASON_ALREADY_REGISTERED, CODE_INVALID_STATE);
        case "TypeError":
            return clientFailure(REASON_VERIFICATION_FAILED, CODE_INVALID_REQUEST);
        default:
            return clientFailure(REASON_VERIFICATION_FAILED, CODE_INVALID_REQUEST);
        }
    };

    const setElementHidden = function (element, hidden) {
        if (element) {
            element.classList.toggle("hidden", hidden);
        }
    };

    const setSecondaryActionsAvailable = function (available) {
        if (!secondaryActions) {
            return;
        }
        secondaryActions.hidden = !available;
        secondaryActions.setAttribute("aria-hidden", available ? "false" : "true");
        secondaryActions.querySelectorAll("button, input, select, textarea, a").forEach(function (control) {
            if (available) {
                control.removeAttribute("disabled");
                control.removeAttribute("aria-disabled");
            } else if ("disabled" in control) {
                control.disabled = true;
            } else {
                control.setAttribute("aria-disabled", "true");
            }
        });
    };

    // Keep the visible UI in Wren:AM's normal auth-screen style while the browser ceremony runs.
    const applyState = function (state, title, help, showRetry) {
        if (passkeyPanel) {
            passkeyPanel.setAttribute("data-passkey-state", state);
            if (state !== "error") {
                passkeyPanel.removeAttribute("data-passkey-failure-reason");
                passkeyPanel.removeAttribute("data-passkey-failure-code");
            }
        }
        if (passkeyHeadingText) {
            passkeyHeadingText.textContent = title;
        }
        if (passkeyHelp) {
            passkeyHelp.textContent = help;
        }
        setElementHidden(waitingPanel, state !== "waiting");
        if (retryButton) {
            retryButton.classList.toggle("hidden", !showRetry);
        }
    };

    const showWaitingState = function () {
        if (passkeyPanel) {
            passkeyPanel.removeAttribute("data-passkey-failure-reason");
            passkeyPanel.removeAttribute("data-passkey-failure-code");
        }
        setSecondaryActionsAvailable(true);
        applyState("waiting",
                textFromAttribute("data-passkey-default-title"),
                textFromAttribute("data-passkey-default-help"),
                false);
    };

    const showFailureState = function (failure, showRetry) {
        setSecondaryActionsAvailable(true);
        if (passkeyPanel && failure) {
            passkeyPanel.setAttribute("data-passkey-failure-reason", failure.reason);
            passkeyPanel.setAttribute("data-passkey-failure-code", failure.code);
        }
        const helpText = failure && failure.reason === REASON_ALREADY_REGISTERED
                ? textFromAttribute("data-passkey-already-registered-help")
                : textFromAttribute("data-passkey-error-help");
        applyState("error",
                textFromAttribute("data-passkey-error-title"),
                helpText,
                showRetry !== false);
    };

    const showSuccessState = function () {
        setSecondaryActionsAvailable(false);
        applyState("success",
                textFromAttribute("data-passkey-success-title"),
                textFromAttribute("data-passkey-success-help"),
                false);
    };

    let completed = false;
    let attemptId = 0;
    let timeoutHandle;
    let abortController;

    const abortRequest = function () {
        if (abortController) {
            abortController.abort();
            abortController = null;
        }
    };

    const clearRequestTimeout = function () {
        if (timeoutHandle) {
            clearTimeout(timeoutHandle);
            timeoutHandle = null;
        }
    };

    const submitSuccess = function (credential) {
        if (completed) {
            return;
        }
        let credentialJson;
        try {
            credentialJson = credentialToJSON(credential);
        } catch (error) {
            showRecoverableFailure(clientFailure(REASON_UNSUPPORTED, CODE_JSON_SERIALIZATION_UNSUPPORTED), false);
            return;
        }
        completed = true;
        attemptId += 1;
        clearRequestTimeout();
        abortController = null;
        output.value = JSON.stringify({
            status: STATUS_OK,
            credential: credentialJson,
        });
        showSuccessState();
        successButton.click();
    };

    const showRecoverableFailure = function (failure, showRetry) {
        if (completed) {
            return;
        }
        clearRequestTimeout();
        abortController = null;
        showFailureState(failure, showRetry);
    };

    errorButton.addEventListener("click", function () {
        if (completed) {
            return;
        }
        completed = true;
        attemptId += 1;
        clearRequestTimeout();
        abortRequest();
        output.value = JSON.stringify({
            status: STATUS_ERROR,
            reason: REASON_USER_CANCELLED,
            message: REASON_USER_CANCELLED,
        });
    });

    if (typeof PublicKeyCredential === "undefined" || !navigator.credentials
            || typeof navigator.credentials.create !== "function") {
        showRecoverableFailure(clientFailure(REASON_UNSUPPORTED), false);
        return;
    }

    let optionsJson;
    try {
        optionsJson = JSON.parse(base64UrlToUtf8(OPTIONS_B64));
    } catch (error) {
        showRecoverableFailure(clientFailure(REASON_VERIFICATION_FAILED, CODE_PARSE_OPTIONS_FAILED), false);
        return;
    }

    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function") {
        showRecoverableFailure(clientFailure(REASON_UNSUPPORTED, CODE_JSON_PARSING_UNSUPPORTED), false);
        return;
    }

    let requestOptions;
    try {
        requestOptions = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJson);
    } catch (error) {
        const failure = toFailure(error);
        showRecoverableFailure(failure, false);
        return;
    }

    if (retryButton) {
        retryButton.addEventListener("click", function () {
            startCredentialCreation();
        });
    }

    function startCredentialCreation() {
        if (completed) {
            return;
        }

        attemptId += 1;
        const currentAttemptId = attemptId;
        abortRequest();
        clearRequestTimeout();
        showWaitingState();

        abortController = typeof AbortController === "function" ? new AbortController() : null;
        const timeoutMs = Math.max((Number(optionsJson.timeout) || 60000) + 10000, 15000);
        timeoutHandle = setTimeout(function () {
            if (completed || currentAttemptId !== attemptId) {
                return;
            }
            abortRequest();
            showRecoverableFailure(clientFailure(REASON_NOT_ALLOWED, CODE_TIMEOUT));
        }, timeoutMs);

        const credentialRequest = { publicKey: requestOptions };
        if (abortController) {
            credentialRequest.signal = abortController.signal;
        }

        navigator.credentials.create(credentialRequest)
            .then(function (credential) {
                if (completed || currentAttemptId !== attemptId) {
                    return;
                }
                submitSuccess(credential);
            })
            .catch(function (error) {
                if (completed || currentAttemptId !== attemptId) {
                    return;
                }
                const failure = toFailure(error);
                showRecoverableFailure(failure);
            });
    }

    startCredentialCreation();
})();
