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
package org.wrensecurity.wrenam.authentication.modules.webauthn.webauthn4j;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import jakarta.inject.Inject;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import org.forgerock.openam.core.rest.devices.webauthn.WebAuthnDeviceSettings;
import org.forgerock.util.Reject;

/**
 * Convert between WebAuthn4J data structures and AM WebAuthn credential records.
 */
public class WebAuthn4JCredentialMapper {

    private final ObjectConverter objectConverter;

    /**
     * Create a WebAuthn4J credential mapper.
     */
    @Inject
    public WebAuthn4JCredentialMapper() {
        this(new ObjectConverter());
    }

    WebAuthn4JCredentialMapper(ObjectConverter objectConverter) {
        Reject.ifNull(objectConverter);
        this.objectConverter = objectConverter;
    }

    /**
     * Convert verified registration data to an AM credential record.
     *
     * @param registrationData verified WebAuthn4J registration data
     * @param root raw browser credential JSON root
     * @return AM credential record
     */
    public WebAuthnDeviceSettings toDeviceSettings(RegistrationData registrationData, JsonNode root) {
        Reject.ifNull(registrationData, root);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData =
                registrationData.getAttestationObject().getAuthenticatorData();
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
        Set<AuthenticatorTransport> transports = registrationData.getTransports() == null
                ? Collections.emptySet()
                : registrationData.getTransports();
        return new WebAuthnDeviceSettings(attestedCredentialData.getCredentialId(),
                objectConverter.getCborConverter().writeValueAsBytes(attestedCredentialData.getCOSEKey()),
                authenticatorData.getSignCount(),
                transports.stream().map(AuthenticatorTransport::getValue).toArray(String[]::new),
                authenticatorData.isFlagBE(), authenticatorData.isFlagBS(),
                decodeRequiredBase64Url(root, "/response/attestationObject"),
                decodeRequiredBase64Url(root, "/response/clientDataJSON"));
    }

    /**
     * Convert a stored AM credential record to a WebAuthn4J credential record.
     *
     * @param device stored AM credential record
     * @return WebAuthn4J credential record
     */
    public CredentialRecord toCredentialRecord(WebAuthnDeviceSettings device) {
        Reject.ifNull(device);
        AttestationObject attestationObject = objectConverter.getCborConverter()
                .readValue(device.getAttestationObject(), AttestationObject.class);
        CollectedClientData clientData = objectConverter.getJsonConverter()
                .readValue(new String(device.getAttestationClientDataJSON(), UTF_8), CollectedClientData.class);
        Set<AuthenticatorTransport> transports = device.getTransports() == null
                ? Collections.emptySet()
                : Arrays.stream(device.getTransports()).map(AuthenticatorTransport::create).collect(Collectors.toSet());
        return new CredentialRecordImpl(
                attestationObject.getAttestationStatement(),
                null,
                device.isBackupEligible(),
                device.isBackupState(),
                device.getSignCount(),
                attestationObject.getAuthenticatorData().getAttestedCredentialData(),
                attestationObject.getAuthenticatorData().getExtensions(),
                clientData,
                null,
                transports);
    }

    private byte[] decodeRequiredBase64Url(JsonNode root, String pointer) {
        JsonNode value = root.at(pointer);
        if (value.isMissingNode() || value.asText().isBlank()) {
            throw new IllegalArgumentException("Missing credential response field " + pointer);
        }
        return Base64.getUrlDecoder().decode(value.asText());
    }
}
