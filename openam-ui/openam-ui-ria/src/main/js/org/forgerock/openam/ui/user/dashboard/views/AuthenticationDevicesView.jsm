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
 * Portions copyright 2025-2026 Wren Security.
 */

import $ from "jquery";
import _ from "lodash";
import moment from "moment";

import {
    remove as removeOAth,
    getAll as getAllOAth
} from "org/forgerock/openam/ui/user/dashboard/services/DeviceManagementService";
import {
    remove as removePush,
    getAll as getAllPush
} from "org/forgerock/openam/ui/user/dashboard/services/PushDeviceService";
import {
    remove as removeWebAuthn,
    getAll as getAllWebAuthn,
    getAcceptedCredentialsSignal
} from "org/forgerock/openam/ui/user/dashboard/services/WebAuthnDeviceService";
import AbstractView from "org/forgerock/commons/ui/common/main/AbstractView";
import DeviceDetailsDialog from "org/forgerock/openam/ui/user/dashboard/views/DeviceDetailsDialog";
import DevicesSettingsDialog from "org/forgerock/openam/ui/user/dashboard/views/DevicesSettingsDialog";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import Promise from "org/forgerock/openam/ui/common/util/Promise";
import showConfirmationBeforeAction from "org/forgerock/openam/ui/admin/utils/form/showConfirmationBeforeAction";

const getAttributeFromElement = (element, attribute) => $(element).closest(`div[${attribute}]`).attr(attribute);
const getUUIDFromElement = (element) => getAttributeFromElement(element, "data-device-uuid");
const getTypeFromElement = (element) => getAttributeFromElement(element, "data-device-type");
const formatCreatedAt = (createdAt) => {
    if (!createdAt) {
        return null;
    }
    const date = moment(createdAt);
    return date.isValid() ? date.format("ll") : null;
};
const addDeviceMetadata = (devices, metadata) => _.map(devices, (device) => {
    const createdAtDisplay = formatCreatedAt(device.createdAt);
    return _.assign({}, device, metadata, createdAtDisplay ? { createdAtDisplay } : {});
});
const handleReject = (response) => {
    Messages.addMessage({
        type: Messages.TYPE_DANGER,
        response
    });
};
const signalAllAcceptedCredentials = () => {
    if (!window.PublicKeyCredential ||
            typeof window.PublicKeyCredential.getClientCapabilities !== "function" ||
            typeof window.PublicKeyCredential.signalAllAcceptedCredentials !== "function") {
        return;
    }
    window.PublicKeyCredential.getClientCapabilities().then((capabilities) => {
        if (!capabilities || capabilities.signalAllAcceptedCredentials !== true) {
            return;
        }
        getAcceptedCredentialsSignal().then((signal) => {
            if (!signal || signal.signalAvailable !== true) {
                return;
            }
            window.PublicKeyCredential.signalAllAcceptedCredentials({
                rpId: signal.rpId,
                userId: signal.userId,
                allAcceptedCredentialIds: _.isArray(signal.allAcceptedCredentialIds)
                    ? signal.allAcceptedCredentialIds
                    : []
            }).catch(_.noop);
        }, _.noop);
    }, _.noop);
};

class DeviceManagementView extends AbstractView {
    constructor () {
        super();
        this.template = "templates/user/dashboard/AuthenticationDevicesTemplate.html";
        this.noBaseTemplate = true;
        this.element = "#authenticationDevices";
        this.events = {
            "click [data-delete]":  "handleDelete",
            "click [data-recovery-codes]": "handleShowDeviceDetails",
            "click [data-details]": "handleShowDeviceDetails",
            "click [data-settings]" : "showDevicesSettings"
        };
    }
    handleDelete (event) {
        event.preventDefault();

        const uuid = getUUIDFromElement(event.currentTarget);
        const type = getTypeFromElement(event.currentTarget);
        const deleteFunc = {
            oath: removeOAth,
            push: removePush,
            passkey: removeWebAuthn
        }[type];

        showConfirmationBeforeAction({
            message: $.t("openam.authDevices.confirmDeleteText", {
                type: $.t(`openam.authDevices.types.${type}`)
            })
        }, () => {
            deleteFunc(uuid).then(() => {
                this.render();
            }, handleReject);
        });
    }
    handleShowDeviceDetails (event) {
        event.preventDefault();

        const uuid = getUUIDFromElement(event.currentTarget);
        const device = _.find(this.data.devices, { uuid });
        const type = getTypeFromElement(event.currentTarget);

        DeviceDetailsDialog(uuid, device, type);
    }
    showDevicesSettings (event) {
        event.preventDefault();

        DevicesSettingsDialog();
    }
    render () {
        Promise.all([getAllOAth(), getAllPush(), getAllWebAuthn()]).then((value) => {
            const oathDevices = addDeviceMetadata(value[0], {
                type: "oath",
                icon: "clock-o"
            });
            const pushDevices = addDeviceMetadata(value[1], {
                type: "push",
                icon: "bell-o"
            });
            const webAuthnDevices = addDeviceMetadata(value[2], {
                type: "passkey",
                icon: "key"
            });

            this.data.hasOathDevices = oathDevices.length > 0;
            this.data.devices = [...oathDevices, ...pushDevices, ...webAuthnDevices];

            this.parentRender();
            signalAllAcceptedCredentials();
        }, handleReject);
    }
}

export default new DeviceManagementView();
