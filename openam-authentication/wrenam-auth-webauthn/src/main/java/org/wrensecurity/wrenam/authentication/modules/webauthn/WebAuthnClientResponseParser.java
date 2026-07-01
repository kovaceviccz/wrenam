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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import java.io.IOException;
import java.util.Locale;
import org.forgerock.util.Reject;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * Get credential JSON from the hidden callback payload returned by WebAuthn client scripts.
 *
 * <p>Successful responses return the raw credential JSON for the WebAuthn library to parse, while
 * client-side failures are represented as {@link WebAuthnClientResponseException}. This keeps the browser callback
 * shape out of the ceremony contracts.
 *
 */
public class WebAuthnClientResponseParser {

    // Keep a hard cap for malformed or abusive payloads
    private static final int MAX_CALLBACK_PAYLOAD_LENGTH = 256 * 1024;

    private static final int MAX_FAILURE_DETAIL_LENGTH = 240;

    private static final String FAILURE_DETAIL_VALIDATION_CONTEXT = "WebAuthn failure detail";

    private static final String FAILURE_DETAIL_VALIDATION_RULE = "HTTPParameterValue";

    private static final String STATUS_OK = "ok";

    private static final String STATUS_ERROR = "error";

    private final ObjectMapper objectMapper;

    /**
     * Create a client response parser.
     */
    @Inject
    public WebAuthnClientResponseParser() {
        this(new ObjectMapper());
    }

    WebAuthnClientResponseParser(ObjectMapper objectMapper) {
        Reject.ifNull(objectMapper);
        this.objectMapper = objectMapper;
    }

    /**
     * Get browser credential JSON from the client script callback payload.
     *
     * @param callbackPayload hidden callback payload produced by the module browser script
     * @param hasError whether the callback state already indicates browser-side cancellation or failure
     * @return browser credential response JSON
     * @throws WebAuthnClientResponseException if the payload reports or implies a client-side failure
     */
    public String getCredentialJson(String callbackPayload, boolean hasError) throws WebAuthnClientResponseException {
        if (callbackPayload == null || callbackPayload.isBlank()) {
            if (hasError) {
                throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, null);
            }
            throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, "Missing WebAuthn response payload.");
        }
        if (callbackPayload.length() > MAX_CALLBACK_PAYLOAD_LENGTH) {
            throw failure(
                    WebAuthnLoginFailureReason.VERIFICATION_FAILED,
                    "WebAuthn response payload exceeded supported size.");
        }

        JsonNode root = parsePayload(callbackPayload);
        if (root == null || !root.isObject()) {
            throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, "Invalid WebAuthn response payload.");
        }

        String status = normalizeStatus(root.path("status").asText(null));
        if (STATUS_OK.equals(status)) {
            return parseSuccessPayload(root, hasError);
        }
        if (STATUS_ERROR.equals(status)) {
            throw parseFailurePayload(root);
        }
        if (hasError) {
            throw failure(WebAuthnLoginFailureReason.NOT_ALLOWED, null);
        }

        throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, "Invalid WebAuthn response status.");
    }

    private String parseSuccessPayload(JsonNode root, boolean hasError) throws WebAuthnClientResponseException {
        if (hasError) {
            throw failure(WebAuthnLoginFailureReason.VERIFICATION_FAILED, "Inconsistent WebAuthn callback state.");
        }
        JsonNode credential = root.get("credential");
        if (credential == null || credential.isNull() || credential.isMissingNode() || !credential.isObject()) {
            throw failure(
                    WebAuthnLoginFailureReason.VERIFICATION_FAILED,
                    "Missing credential in WebAuthn success payload.");
        }
        return credential.toString();
    }

    private WebAuthnClientResponseException parseFailurePayload(JsonNode root) {
        WebAuthnLoginFailureReason reason = WebAuthnLoginFailureReason.fromReasonCode(root.path("reason").asText(null));
        String message = sanitizeFailureDetail(root.path("message").asText(null));
        return failure(reason, message);
    }

    private JsonNode parsePayload(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (IOException e) {
            return null;
        }
    }

    private String normalizeStatus(String status) {
        if (status == null || status.isBlank()) {
            return null;
        }
        return status.trim().toLowerCase(Locale.ROOT);
    }

    private String sanitizeFailureDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return null;
        }

        try {
            return ESAPI.validator().getValidInput(
                    FAILURE_DETAIL_VALIDATION_CONTEXT,
                    detail.trim(),
                    FAILURE_DETAIL_VALIDATION_RULE,
                    MAX_FAILURE_DETAIL_LENGTH,
                    false);
        } catch (ValidationException | IntrusionException e) {
            return null;
        }
    }

    private WebAuthnClientResponseException failure(WebAuthnLoginFailureReason reason, String message) {
        return new WebAuthnClientResponseException(reason, message);
    }

}
