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

import { bindActionCreators } from "redux";
import { find, get, map, result } from "lodash";
import PropTypes from "prop-types";
import React, { Component } from "react";

import { getAllTypes, getSchema, getTemplate, create }
    from "org/forgerock/openam/ui/admin/services/realm/identities/UsersServicesService";
import { setSchema } from "store/modules/remote/config/realm/identities/users/services/schema";
import { setTemplate } from "store/modules/remote/config/realm/identities/users/services/template";
import connectWithStore from "components/redux/connectWithStore";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import NewUserService from "./NewUserService";
import Router from "org/forgerock/commons/ui/common/main/Router";
import withRouter from "org/forgerock/commons/ui/common/components/hoc/withRouter";
import withRouterPropType from "org/forgerock/commons/ui/common/components/hoc/withRouterPropType";

class NewUserServiceContainer extends Component {
    constructor () {
        super();
        this.state = {
            isFetching: true,
            type: ""
        };
    }

    componentDidMount () {
        const [realm, userId, serviceId] = this.props.router.params;
        this.props.setTemplate(null, serviceId);
        this.props.setSchema(null, serviceId);

        Promise.all([
            getSchema(realm, serviceId, userId),
            getTemplate(realm, serviceId, userId),
            getAllTypes(realm, userId)
        ])
            .then(([schema, template, serviceTypes]) => {
                if (this.isUnmounted) {
                    return;
                }
                this.props.setTemplate(template, serviceId);
                this.props.setSchema(schema, serviceId);
                this.setState({
                    type: result(find(serviceTypes.result, { "_id": serviceId }), "name", serviceId),
                    isFetching: false
                });
            }, (response) => {
                if (this.isUnmounted) {
                    return;
                }
                this.setState({ isFetching: false });
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            });
    }

    componentWillUnmount () {
        this.isUnmounted = true;
    }

    handleCreate = (formData) => {
        const [realm, userId, serviceId] = this.props.router.params;

        create(realm, userId, serviceId, formData).then(() => {
            if (this.isUnmounted) {
                return;
            }
            Router.routeTo(Router.configuration.routes.realmsIdentitiesUsersServicesEdit,
                { args: map([realm, userId, serviceId], encodeURIComponent), trigger: true });
        }, (response) => {
            if (!this.isUnmounted) {
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            }
        });
    };

    render () {
        const userId = this.props.router.params[1];

        return (
            <NewUserService
                id={ userId }
                isFetching={ this.state.isFetching }
                onCreate={ this.handleCreate }
                schema={ this.props.schema }
                template={ this.props.template }
                type={ this.state.type }
            />
        );
    }
}

NewUserServiceContainer.propTypes = {
    router: withRouterPropType,
    schema: PropTypes.shape({
        properties: PropTypes.objectOf(PropTypes.object),
        type: PropTypes.string
    }),
    setSchema: PropTypes.func.isRequired,
    setTemplate: PropTypes.func.isRequired,
    template: PropTypes.objectOf(PropTypes.any)
};

NewUserServiceContainer = connectWithStore(NewUserServiceContainer,
    (state, props) => {
        const serviceId = props.router.params[2];

        return {
            schema: get(state.remote.config.realm.identities.users.services.schema, serviceId),
            template: get(state.remote.config.realm.identities.users.services.template, serviceId)
        };
    },
    (dispatch) => ({
        setSchema: bindActionCreators(setSchema, dispatch),
        setTemplate: bindActionCreators(setTemplate, dispatch)
    })
);
NewUserServiceContainer = withRouter(NewUserServiceContainer);

export default NewUserServiceContainer;
