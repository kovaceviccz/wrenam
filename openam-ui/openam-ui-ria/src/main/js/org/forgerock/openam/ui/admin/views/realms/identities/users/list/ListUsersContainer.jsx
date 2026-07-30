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
 * Copyright 2018-2022 ForgeRock AS.
 * Portions copyright 2026 Wren Security.
 */
import { bindActionCreators } from "redux";
import { isEmpty, isEqual, map, pick } from "lodash";
import { t } from "i18next";
import PropTypes from "prop-types";
import React, { Component } from "react";

import { searchUsers, remove } from "org/forgerock/openam/ui/admin/services/realm/identities/UsersService";
import { setInstances } from "store/modules/remote/config/realm/identities/users/instances";
import connectWithStore from "components/redux/connectWithStore";
import ListUsers from "./ListUsers";
import Messages from "org/forgerock/commons/ui/common/components/Messages";
import Router from "org/forgerock/commons/ui/common/main/Router";
import showConfirmationBeforeAction from "org/forgerock/openam/ui/admin/utils/form/showConfirmationBeforeAction";
import withPagination, { withPaginationPropTypes }
    from "org/forgerock/openam/ui/admin/views/realms/common/withPagination";
import withRouter from "org/forgerock/commons/ui/common/components/hoc/withRouter";
import withRouterPropType from "org/forgerock/commons/ui/common/components/hoc/withRouterPropType";

const REQUEST_PAGINATION_FIELDS = [
    "page", "pagedResultsOffset", "searchTerm", "sizePerPage", "sortDirection", "sortKey"
];

class ListUsersContainer extends Component {
    static propTypes = {
        identities: PropTypes.arrayOf(PropTypes.object),
        pagination: withPaginationPropTypes,
        router: withRouterPropType,
        setInstances: PropTypes.func.isRequired
    };

    state = {
        isFetching: true
    };

    componentDidMount () {
        this.props.setInstances([]);
        this.handleTableDataChange(this.props.pagination);
    }

    // eslint-disable-next-line camelcase
    UNSAFE_componentWillReceiveProps (nextProps) {
        if (!isEqual(pick(this.props.pagination, REQUEST_PAGINATION_FIELDS),
            pick(nextProps.pagination, REQUEST_PAGINATION_FIELDS))) {
            this.handleTableDataChange(nextProps.pagination);
        }
    }

    componentWillUnmount () {
        this.isUnmounted = true;
    }

    handleDelete = (items) => {
        const ids = map(items, "_id");
        const message = t("console.identities.users.confirmDeleteSelected", { count: ids.length });

        showConfirmationBeforeAction({ message }, () => {
            const realm = this.props.router.params[0];
            remove(realm, ids).then(() => {
                Messages.addMessage({ message: t("config.messages.AppMessages.changesSaved") });
                const pagination = this.props.pagination;
                const movesToPreviousPage = pagination.onDataDelete(ids.length);
                if (!movesToPreviousPage) {
                    this.handleTableDataChange(pagination);
                }
            }, (response) => {
                this.handleTableDataChange(this.props.pagination);
                Messages.addMessage({ response, type: Messages.TYPE_DANGER });
            });
        });
    };

    handleEdit = (e, item) => {
        const id = item._id;
        const realm = this.props.router.params[0];

        Router.routeTo(Router.configuration.routes.realmsIdentitiesUsersEdit, {
            args: map([realm, id], encodeURIComponent),
            trigger: true
        });
    };

    handleTableDataChange = (pagination) => {
        const realm = this.props.router.params[0];
        const additionalParams = {
            fields: ["cn", "mail", "username", "inetUserStatus"],
            pagination: {
                ...pagination,
                sortKey: pagination.sortKey || "username"
            }
        };
        searchUsers(realm, additionalParams).then((response) => {
            if (this.isUnmounted || realm !== this.props.router.params[0] ||
                !isEqual(pick(pagination, REQUEST_PAGINATION_FIELDS),
                    pick(this.props.pagination, REQUEST_PAGINATION_FIELDS))) {
                return;
            }
            this.setState({ isFetching: false });
            this.props.pagination.onDataChange(response);
            this.props.setInstances(response.result);
        }, (response) => {
            if (this.isUnmounted || realm !== this.props.router.params[0] ||
                !isEqual(pick(pagination, REQUEST_PAGINATION_FIELDS),
                    pick(this.props.pagination, REQUEST_PAGINATION_FIELDS))) {
                return;
            }
            this.setState({ isFetching: false });
            this.props.setInstances([]);
            Messages.addMessage({ response, type: Messages.TYPE_DANGER });
        });
    };

    render () {
        const realm = this.props.router.params[0];
        const newHref = Router.getLink(Router.configuration.routes.realmsIdentitiesUsersNew, [
            encodeURIComponent(realm)
        ]);

        return (
            <ListUsers
                isFetching={ this.state.isFetching }
                isSearching={ !isEmpty(this.props.pagination.searchTerm) }
                items={ this.props.identities }
                newHref={ `#${newHref}` }
                onDelete={ this.handleDelete }
                onRowClick={ this.handleEdit }
                onSearchKeyPress={ this.props.pagination.handleSearchChange }
                options={ {
                    ...this.props.pagination
                } }
                searchTerm={ this.props.pagination.searchTerm }
            />
        );
    }
}

ListUsersContainer = connectWithStore(ListUsersContainer,
    (state) => ({
        identities: state.remote.config.realm.identities.users.instances
    }),
    (dispatch) => ({
        setInstances: bindActionCreators(setInstances, dispatch)
    })
);
ListUsersContainer = withRouter(ListUsersContainer);
ListUsersContainer = withPagination(ListUsersContainer);

export default ListUsersContainer;
