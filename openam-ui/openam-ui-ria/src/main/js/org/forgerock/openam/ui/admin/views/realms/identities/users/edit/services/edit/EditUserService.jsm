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
 * Copyright 2018-2019 ForgeRock AS.
 * Portions copyright 2026 Wren Security.
 */

import { find, isEqual, map, result } from "lodash";
import { t } from "i18next";

import { getAllTypes, getSchema, get as getUserService, remove, update } from
    "org/forgerock/openam/ui/admin/services/realm/identities/UsersServicesService";
import AbstractView from "org/forgerock/commons/ui/common/main/AbstractView";
import FlatJSONSchemaView from "org/forgerock/openam/ui/common/views/jsonSchema/FlatJSONSchemaView";
import JSONSchema from "org/forgerock/openam/ui/common/models/JSONSchema";
import JSONValues from "org/forgerock/openam/ui/common/models/JSONValues";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import Router from "org/forgerock/commons/ui/common/main/Router";
import showConfirmationBeforeAction from "org/forgerock/openam/ui/admin/utils/form/showConfirmationBeforeAction";
import ViewManager from "org/forgerock/commons/ui/common/main/ViewManager";

class EditUserService extends AbstractView {
    constructor () {
        super();

        this.template = "templates/admin/views/realms/identities/users/services/EditUserServiceTemplate.html";

        this.events = {
            "click [data-delete]": "onDelete",
            "click [data-save]": "onSave"
        };
    }

    render (args) {
        const [realm, userId, type] = args;
        const route = Router.currentRoute;
        const viewArgs = ViewManager.currentViewArgs;
        this.route = route;
        this.viewArgs = viewArgs;
        const currentArgs = map(viewArgs, (arg) => (arg && decodeURIComponent(arg)) || "");
        if (!isEqual(args, currentArgs)) {
            return;
        }

        if (this.view) {
            this.view.destroy();
            this.view.remove();
            this.view = null;
        }

        this.data = {
            id: userId,
            saveDisabled: true,
            headerActions: [{
                actionPartial: "form/_Button", data: "delete", title: "common.form.delete", icon: "fa-times"
            }]
        };
        this.realm = realm;
        this.type = type;

        Promise.all([
            getSchema(realm, type, userId),
            getUserService(realm, type, userId),
            getAllTypes(realm, userId)
        ]).then(([schema, service, serviceTypes]) => {
            if (!this.isCurrentView(route, viewArgs)) {
                return;
            }
            const editorSchema = new JSONSchema(schema);
            const editorValues = new JSONValues(service);
            this.data.type = t("console.identities.users.edit.services.edit.subtitle", {
                type: result(find(serviceTypes.result, { "_id": type }), "name", type)
            });

            this.parentRender(() => {
                if (!this.isCurrentView(route, viewArgs)) {
                    return;
                }
                this.view = new FlatJSONSchemaView({
                    schema: editorSchema,
                    values: editorValues,
                    onRendered: () => this.handleEditorRendered(route, viewArgs)
                });
                this.view.setElement(this.$("[data-json-form]"));
                this.view.render();
            });
        }, (response) => {
            if (this.isCurrentView(route, viewArgs)) {
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            }
        });
    }

    isCurrentView (route, viewArgs) {
        return this.route === route && route === Router.currentRoute &&
            this.viewArgs === viewArgs && viewArgs === ViewManager.currentViewArgs;
    }

    handleEditorRendered (route, viewArgs) {
        if (this.isCurrentView(route, viewArgs)) {
            this.$("[data-save]").prop("disabled", false);
        }
    }

    onSave () {
        if (!this.view) {
            return;
        }

        if (!this.view.isValid()) {
            Messages.addMessage({
                message: t("common.form.validation.errorsNotSaved"), type: Messages.TYPE_DANGER
            });
            return;
        }

        const route = this.route;
        const viewArgs = this.viewArgs;
        const realm = this.realm;
        const type = this.type;
        const id = this.data.id;
        this.$("[data-save]").prop("disabled", true);
        update(realm, type, id, this.view.getData()).then(() => {
            if (!this.isCurrentView(route, viewArgs)) {
                return null;
            }
            return getUserService(realm, type, id);
        }).then((service) => {
            if (!service || !this.isCurrentView(route, viewArgs)) {
                return;
            }
            this.view.setData(service);
            this.$("[data-save]").prop("disabled", false);
            Messages.addMessage({ message: t("config.messages.AppMessages.changesSaved") });
        }, (response) => {
            if (this.isCurrentView(route, viewArgs)) {
                this.$("[data-save]").prop("disabled", false);
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            }
        });
    }

    onDelete () {
        const route = this.route;
        const viewArgs = this.viewArgs;
        const realm = this.realm;
        const type = this.type;
        const id = this.data.id;
        showConfirmationBeforeAction({
            message: t("console.identities.users.edit.services.confirmDeleteSelected", { count: 1 })
        }, () => {
            if (!this.isCurrentView(route, viewArgs)) {
                return;
            }
            remove(realm, id, [type]).then(() => {
                if (!this.isCurrentView(route, viewArgs)) {
                    return;
                }
                Messages.addMessage({ message: t("config.messages.AppMessages.changesSaved") });
                Router.routeTo(Router.configuration.routes.realmsIdentitiesUsersEdit, {
                    args: map([realm, id], encodeURIComponent),
                    trigger: true
                });
            }, (response) => {
                if (this.isCurrentView(route, viewArgs)) {
                    Messages.addMessage({ response, type: Messages.TYPE_DANGER });
                }
            });
        });
    }
}

export default EditUserService;
