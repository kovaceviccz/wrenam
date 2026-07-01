/**
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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2026 Wren Security.
 */

define([
    "jquery",
    "lodash",
    "org/forgerock/commons/ui/common/components/BootstrapDialog",
    "org/forgerock/commons/ui/common/util/UIUtils",
    "org/forgerock/openam/ui/user/dashboard/services/WebAuthnDeviceService"
], ($, _, BootstrapDialog, UIUtils, WebAuthnDeviceService) => {
    /**
     * Builds the template data purely from the device state, so the dialog renders identically for every
     * device type. The behavioural difference is driven by data alone: sealed devices (WebAuthn after its
     * one-time reveal) carry no plaintext codes and expose only a remaining count, while unsealed devices
     * (OATH/Push) always carry their codes and therefore always display them.
     *
     * @param {object} device the merged device record
     * @param {string} type the device type marker
     * @param {object} [revealedState] freshly regenerated recovery-code state to display once, if any
     * @returns {object} template data
     */
    const buildData = (device, type, revealedState) => {
        const codes = _.isArray(_.get(revealedState, "recoveryCodes"))
            ? revealedState.recoveryCodes
            : (_.isArray(device.recoveryCodes) ? device.recoveryCodes : null);
        const hasCodes = _.isArray(codes) && codes.length > 0;
        const sealed = _.isBoolean(_.get(revealedState, "recoveryCodesSealed"))
            ? revealedState.recoveryCodesSealed
            : device.recoveryCodesSealed === true;
        const deviceRecoveryCodesRemaining = _.isNumber(device.recoveryCodesRemaining)
            ? device.recoveryCodesRemaining
            : (hasCodes ? codes.length : 0);
        const recoveryCodesRemaining = _.isNumber(_.get(revealedState, "recoveryCodesRemaining"))
            ? revealedState.recoveryCodesRemaining
            : deviceRecoveryCodesRemaining;
        return {
            deviceName: device.deviceName,
            deviceType: type,
            createdAtDisplay: device.createdAtDisplay,
            sealed,
            hasCodes,
            justRevealed: _.isArray(_.get(revealedState, "recoveryCodes")),
            recoveryCodesRemaining,
            recoveryCodes: hasCodes ? codes.join("\n") : ""
        };
    };

    const exposeDialogToAssistiveTechnology = (dialog) => {
        // bootstrap-dialog leaves the modal marked aria-hidden after opening; clear that state here so
        // visible device details, including freshly revealed recovery codes, are reachable by assistive tools.
        dialog.getModal().attr({
            "aria-hidden": "false",
            "aria-modal": "true"
        });
    };

    return function (uuid, device, type) {
        const $message = $("<div>");

        const renderBody = (data) =>
            UIUtils.compileTemplate("templates/user/dashboard/EditDeviceDialogTemplate.html", data).then((tpl) => {
                $message.html(tpl);
                $message.find("[data-regenerate-recovery-codes]").one("click", (event) => {
                    event.preventDefault();
                    const button = $(event.currentTarget);
                    button.prop("disabled", true);
                    WebAuthnDeviceService.regenerateRecoveryCodes(uuid).then((response) => {
                        // Surface the new plaintext codes exactly once; the backend has already re-sealed them.
                        renderBody(buildData(device, type, response));
                    }, () => {
                        button.prop("disabled", false);
                    });
                });
            });

        renderBody(buildData(device, type));

        BootstrapDialog.show({
            title: device.deviceName,
            message: $message,
            cssClass: "device-details",
            onshow: exposeDialogToAssistiveTechnology,
            onshown: exposeDialogToAssistiveTechnology,
            buttons: [{
                label: $.t("common.form.close"),
                action: (dialog) => {
                    dialog.close();
                }
            }]
        });
    };
});
