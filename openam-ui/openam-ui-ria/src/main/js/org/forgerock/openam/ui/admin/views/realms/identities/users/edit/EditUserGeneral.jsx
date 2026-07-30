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

import { Panel } from "react-bootstrap";
import React, { Component } from "react";
import { t } from "i18next";
import { cloneDeep, get, includes, isArray, isEmpty, mapValues, omitBy, reduce } from "lodash";

import { get as getUser, getSchema, update }
    from "org/forgerock/openam/ui/admin/services/realm/identities/UsersService";
import EditFooter from "org/forgerock/openam/ui/admin/views/realms/common/EditFooter";
import FlatJSONSchemaView from "org/forgerock/openam/ui/common/views/jsonSchema/FlatJSONSchemaView";
import JSONSchema from "org/forgerock/openam/ui/common/models/JSONSchema";
import JSONValues from "org/forgerock/openam/ui/common/models/JSONValues";
import Loading from "components/Loading";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import withRouter from "org/forgerock/commons/ui/common/components/hoc/withRouter";
import withRouterPropType from "org/forgerock/commons/ui/common/components/hoc/withRouterPropType";

const arrayifyEmptyStringValues = (values, schema) => {
    return mapValues(values, (value, key) => {
        if (schema.properties[key].type === "string" && value === "") {
            return [];
        }
        return value;
    });
};

const flattenArrayStringValues = (values, schema) => {
    return mapValues(values, (value, key) => {
        const schemaProperty = schema.properties[key];
        if (schemaProperty && schemaProperty.type === "string" && isArray(value)) {
            return value[0];
        }
        return value;
    });
};

const removeValuesNotInSchema = (values, schema) => {
    return reduce(values, (result, value, key) => {
        const schemaProperty = schema.properties[key];
        if (schemaProperty) {
            result[key] = value;
        }
        return result;
    }, {});
};

class EditUserGeneral extends Component {
    constructor (props) {
        super(props);

        this.state = {
            isEditorReady: false,
            isFetching: true,
            isSaving: false
        };
    }

    componentDidMount () {
        const realm = this.props.router.params[0];
        const id = this.props.router.params[1];
        Promise.all([getSchema(realm), getUser(realm, id)]).then(([schema, values]) => {
            if (this.isUnmounted) {
                return;
            }
            const editableSchema = cloneDeep(schema);
            const passwordProperty = get(editableSchema, "properties.userPassword");
            if (passwordProperty) {
                passwordProperty.required = false;
                delete passwordProperty.minLength;
            }

            this.schema = new JSONSchema(editableSchema);
            this.values = flattenArrayStringValues(removeValuesNotInSchema(values, editableSchema), editableSchema);
            this.setState({ isFetching: false });
        }, (response) => {
            if (this.isUnmounted) {
                return;
            }
            this.setState({ isFetching: false });
            Messages.addMessage({ response, type: Messages.TYPE_DANGER });
        });
    }

    componentDidUpdate () {
        if (!this.jsonSchemaView && this.schema && this.values) {
            this.jsonSchemaView = new FlatJSONSchemaView({
                schema: this.schema,
                values: new JSONValues(this.values),
                onRendered: this.handleEditorRendered
            });
            this.element.appendChild(this.jsonSchemaView.render().el);
        }
    }

    componentWillUnmount () {
        this.isUnmounted = true;
        if (this.jsonSchemaView) {
            this.jsonSchemaView.destroy();
        }
    }

    handleSave = () => {
        if (!this.jsonSchemaView || this.state.isSaving) {
            return;
        }
        if (!this.jsonSchemaView.isValid()) {
            Messages.addMessage({ message: t("common.form.validation.errorsNotSaved"), type: Messages.TYPE_DANGER });
            return;
        }
        const formValues = this.jsonSchemaView.getData();
        const valuesFromSchema = removeValuesNotInSchema(formValues, this.schema.raw);
        const passwordKeys = this.schema.getPasswordKeys();
        const valuesWithoutBlankPasswords = omitBy(valuesFromSchema,
            (value, key) => includes(passwordKeys, key) && isEmpty(value));
        const values = arrayifyEmptyStringValues(valuesWithoutBlankPasswords, this.schema.raw);

        const realm = this.props.router.params[0];
        const id = this.props.router.params[1];

        this.setState({ isSaving: true });
        update(realm, values, id).then(() => {
            if (!this.isUnmounted) {
                this.setState({ isSaving: false });
                Messages.addMessage({ message: t("config.messages.AppMessages.changesSaved") });
            }
        }, (response) => {
            if (!this.isUnmounted) {
                this.setState({ isSaving: false });
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            }
        });
    };

    handleEditorRendered = () => {
        if (!this.isUnmounted) {
            this.setState({ isEditorReady: true });
        }
    };

    setRef = (element) => {
        this.element = element;
    };

    render () {
        const content = this.state.isFetching
            ? <Loading />
            : <div ref={ this.setRef } />;

        return (
            <Panel className="fr-panel-tab">
                <Panel.Body>{ content }</Panel.Body>
                <Panel.Footer>
                    <EditFooter
                        disabled={ !this.state.isEditorReady || this.state.isSaving }
                        onSaveClick={ this.handleSave }
                    />
                </Panel.Footer>
            </Panel>
        );
    }
}

EditUserGeneral.propTypes = {
    router: withRouterPropType
};

export default withRouter(EditUserGeneral);
