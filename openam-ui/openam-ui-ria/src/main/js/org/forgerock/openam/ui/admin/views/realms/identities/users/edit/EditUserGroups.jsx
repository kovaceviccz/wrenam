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

import { assign, cloneDeep, get, map, reduce } from "lodash";
import { Form, Panel } from "react-bootstrap";
import { t } from "i18next";
import React, { Component } from "react";

import { getAll as getAllGroups }
    from "org/forgerock/openam/ui/admin/services/realm/identities/GroupsService";
import { get as getGroups, update, getSchema }
    from "org/forgerock/openam/ui/admin/services/realm/identities/UsersGroupsService";
import EditFooter from "org/forgerock/openam/ui/admin/views/realms/common/EditFooter";
import FlatJSONSchemaView from "org/forgerock/openam/ui/common/views/jsonSchema/FlatJSONSchemaView";
import JSONSchema from "org/forgerock/openam/ui/common/models/JSONSchema";
import JSONValues from "org/forgerock/openam/ui/common/models/JSONValues";
import Loading from "components/Loading";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import withRouter from "org/forgerock/commons/ui/common/components/hoc/withRouter";
import withRouterPropType from "org/forgerock/commons/ui/common/components/hoc/withRouterPropType";

class EditUserGroups extends Component {
    constructor (props) {
        super(props);

        this.state = {
            isEditorReady: false,
            isFetching: true
        };
    }

    componentDidMount () {
        const realm = this.props.router.params[0];
        const id = this.props.router.params[1];
        Promise.all([
            getSchema(realm, id),
            getGroups(realm, id),
            getAllGroups(realm, { fields: ["name"] })
        ]).then(([schema, values, allGroups]) => {
            this.values = {
                groups: map(values.result, "_id")
            };
            this.schema = this.addGroupsSelectionToTheSchema(schema, allGroups.result);
            this.setState({ isFetching: false });
        }, (response) => {
            this.setState({ isFetching: false });
            Messages.addMessage({ response, type: Messages.TYPE_DANGER });
        });
    }

    componentDidUpdate () {
        if (!this.jsonSchemaView && this.schema && this.values) {
            this.jsonSchemaView = new FlatJSONSchemaView({
                schema: new JSONSchema(this.schema),
                values: new JSONValues(this.values),
                onRendered: this.handleEditorRendered
            });
            this.element.appendChild(this.jsonSchemaView.render().el);
        }
    }

    componentWillUnmount () {
        if (this.jsonSchemaView) {
            this.jsonSchemaView.destroy();
        }
    }

    addGroupsSelectionToTheSchema (schema, groups) {
        const schemaCopy = cloneDeep(schema);
        const groupsProperty = get(schemaCopy, "properties.groups.items");
        if (groupsProperty) {
            const parsedGroups = reduce(groups, (property, group) => {
                property.enum.push(group._id);
                property.options.enum_titles.push(group.name || group._id);
                return property;
            }, { "enum": [], "options": { "enum_titles": [] } });
            assign(groupsProperty, parsedGroups);
        } else {
            console.error("[EditUserGroups] Unable to add available groups to 'groups' property.");
        }
        return schemaCopy;
    }

    handleSave = () => {
        if (!this.jsonSchemaView.isValid()) {
            Messages.addMessage({ message: t("common.form.validation.errorsNotSaved"), type: Messages.TYPE_DANGER });
            return;
        }

        const realm = this.props.router.params[0];
        const id = this.props.router.params[1];
        const groups = get(this.jsonSchemaView.getData(), "groups", []);
        this.setState({ isEditorReady: false });

        update(realm, id, groups).then(() => getGroups(realm, id)).then((values) => {
            this.jsonSchemaView.setData({ groups: map(values.result, "_id") });
            this.setState({ isEditorReady: true });
            Messages.addMessage({ message: t("config.messages.AppMessages.changesSaved") });
        }, (response) => {
            this.setState({ isEditorReady: true });
            Messages.addMessage({ response, type: Messages.TYPE_DANGER });
        });
    };

    handleEditorRendered = () => {
        this.setState({ isEditorReady: true });
    };

    setRef = (element) => {
        this.element = element;
    };

    render () {
        const content = this.state.isFetching
            ? <Loading />
            : (
                <Form horizontal>
                    <div ref={ this.setRef } />
                </Form>
            );

        return (
            <Panel className="fr-panel-tab">
                <Panel.Body>{ content }</Panel.Body>
                <Panel.Footer>
                    <EditFooter disabled={ !this.state.isEditorReady } onSaveClick={ this.handleSave } />
                </Panel.Footer>
            </Panel>
        );
    }
}

EditUserGroups.propTypes = {
    router: withRouterPropType
};

export default withRouter(EditUserGroups);
