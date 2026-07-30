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
 * Copyright 2018-2020 ForgeRock AS.
 * Portions copyright 2026 Wren Security.
 */

import { Form, Panel } from "react-bootstrap";
import { t } from "i18next";
import PropTypes from "prop-types";
import React, { Component } from "react";

import CreateFooter from "org/forgerock/openam/ui/admin/views/realms/common/CreateFooter";
import FlatJSONSchemaView from "org/forgerock/openam/ui/common/views/jsonSchema/FlatJSONSchemaView";
import FormGroupInput from "org/forgerock/openam/ui/admin/views/realms/common/FormGroupInput";
import JSONSchema from "org/forgerock/openam/ui/common/models/JSONSchema";
import JSONValues from "org/forgerock/openam/ui/common/models/JSONValues";
import Loading from "components/Loading";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import PageHeader from "components/PageHeader";
import Router from "org/forgerock/commons/ui/common/main/Router";

class NewUser extends Component {
    constructor (props) {
        super(props);

        this.state = {
            isEditorReady: false
        };
    }

    componentDidUpdate () {
        if (!this.jsonSchemaView && this.props.schema && this.props.template && this.jsonForm) {
            this.jsonSchemaView = new FlatJSONSchemaView({
                hideInheritance: true,
                schema: new JSONSchema(this.props.schema),
                values: new JSONValues(this.props.template),
                showOnlyRequiredAndEmpty: true,
                onRendered: this.handleEditorRendered
            });
            this.jsonForm.appendChild(this.jsonSchemaView.render().el);
        }
    }

    componentWillUnmount () {
        if (this.jsonSchemaView) {
            this.jsonSchemaView.destroy();
        }
    }

    handleCreate = () => {
        if (!this.jsonSchemaView.isValid()) {
            Messages.addMessage({ message: t("common.form.validation.errorsNotSaved"), type: Messages.TYPE_DANGER });
            return;
        }
        this.props.onCreate(this.jsonSchemaView.getData());
    };

    handleEditorRendered = () => {
        this.setState({ isEditorReady: true });
    };

    setRef = (element) => {
        this.jsonForm = element;
    };

    render () {
        let content;

        if (this.props.isFetching) {
            content = <Loading />;
        } else {
            content = (
                <Form horizontal>
                    <FormGroupInput
                        isValid={ this.props.isValidId }
                        label={ t("console.identities.users.new.userId") }
                        onChange={ this.props.onIdChange }
                        validationMessage={ t("console.common.validation.invalidCharacters") }
                        value={ this.props.id }
                    />
                    <div ref={ this.setRef } />
                    <FormGroupInput
                        isValid={ this.props.isValidEmail }
                        label={ t("console.identities.users.new.emailAddress") }
                        onChange={ this.props.onEmailChange }
                        type="email"
                        validationMessage={ t("common.form.validation.VALID_EMAIL_ADDRESS_FORMAT") }
                        value={ this.props.email }
                    />
                </Form>
            );
        }

        return (
            <div>
                <PageHeader title={ t("console.identities.users.new.title") } />
                <Panel>
                    <Panel.Body>{ content }</Panel.Body>
                    <Panel.Footer>
                        <CreateFooter
                            backRoute={ Router.configuration.routes.realmsIdentities }
                            disabled={ !this.props.isCreateAllowed || !this.state.isEditorReady }
                            onCreateClick={ this.handleCreate }
                        />
                    </Panel.Footer>
                </Panel>
            </div>
        );
    }
}

NewUser.propTypes = {
    email: PropTypes.string.isRequired,
    id: PropTypes.string.isRequired,
    isCreateAllowed: PropTypes.bool.isRequired,
    isFetching: PropTypes.bool.isRequired,
    isValidEmail: PropTypes.bool.isRequired,
    isValidId: PropTypes.bool.isRequired,
    onCreate: PropTypes.func.isRequired,
    onEmailChange: PropTypes.func.isRequired,
    onIdChange: PropTypes.func.isRequired,
    schema: PropTypes.shape({
        properties: PropTypes.objectOf(PropTypes.object),
        type: PropTypes.string
    }),
    template: PropTypes.objectOf(PropTypes.any)
};

export default NewUser;
