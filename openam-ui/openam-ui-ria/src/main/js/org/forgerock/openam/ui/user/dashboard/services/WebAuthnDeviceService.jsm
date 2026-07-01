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
 * Copyright 2016 ForgeRock AS.
 * Portions copyright 2025 Wren Security.
 */
import AbstractDelegate from "org/forgerock/commons/ui/common/main/AbstractDelegate";
import Configuration from "org/forgerock/commons/ui/common/main/Configuration";
import Constants from "org/forgerock/commons/ui/common/util/Constants";
import fetchUrl from "org/forgerock/openam/ui/common/services/fetchUrl";

const delegate = new AbstractDelegate(`${Constants.host}/${Constants.context}/json`);
const getPath = function () {
    return `/users/${Configuration.loggedUser.get("uid")}/devices/webauthn/`;
};

export function getAll () {
    return delegate.serviceCall({
        url: fetchUrl(`${getPath()}?_queryFilter=true`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        suppressEvents: true
    }).then((value) => value.result);
}

export function remove (uuid) {
    return delegate.serviceCall({
        url: fetchUrl(getPath() + uuid),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        suppressEvents: true,
        method: "DELETE"
    });
}

/**
 * Get the WebAuthn signal payload for the browser's accepted-credentials sync API.
 *
 * @returns {Promise} resolving to a {@code signalAllAcceptedCredentials} payload or {@code signalAvailable: false}.
 */
export function getAcceptedCredentialsSignal () {
    return delegate.serviceCall({
        url: fetchUrl(`${getPath()}?_action=signalAllAcceptedCredentials`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        data: "{}",
        suppressEvents: true,
        method: "POST"
    });
}

/**
 * Invalidate the device's existing recovery codes and obtain a freshly generated set. The plaintext
 * codes are returned exactly once in the action response; sealed devices never disclose them again on read.
 *
 * @param {string} uuid identifier of the WebAuthn device
 * @returns {Promise} resolving to the action response containing the new {@code recoveryCodes}.
 */
export function regenerateRecoveryCodes (uuid) {
    return delegate.serviceCall({
        url: fetchUrl(`${getPath()}${uuid}?_action=regenerateRecoveryCodes`),
        headers: { "Accept-API-Version": "protocol=1.0,resource=1.0" },
        data: "{}",
        suppressEvents: true,
        method: "POST"
    });
}
