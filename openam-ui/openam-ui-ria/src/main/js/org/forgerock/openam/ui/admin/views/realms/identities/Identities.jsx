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
 * Copyright 2017-2019 ForgeRock AS.
 * Portions copyright 2025 Wren Security.
 */

import { Tab, Tabs } from "react-bootstrap";
import { t } from "i18next";
import React from "react";

import ListGroupsContainer from "./groups/list/ListGroupsContainer";
import PageHeader from "components/PageHeader";

import withRouter from "org/forgerock/commons/ui/common/components/hoc/withRouter";

const Identities = () => {
    return (
        <div>
            <PageHeader title={ t("console.identities.title") } />
            <Tabs animation={ false } defaultActiveKey={ 1 } id="identities" mountOnEnter unmountOnExit>
                <Tab eventKey={ 1 } title={ t("console.identities.tabs.0") }>
                    <ListGroupsContainer />
                </Tab>
            </Tabs>
        </div>
    );
};

export default withRouter(Identities);
