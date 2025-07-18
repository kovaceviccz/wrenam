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
 * Copyright 2019 ForgeRock AS.
 * Portions copyright 2025 Wren Security.
 */

import { components } from "react-select";
import classnames from "classnames";
import PropTypes from "prop-types";
import React from "react";

import EmphasizedText from "components/EmphasizedText";

/*
 * This custom DefaultOption component wraps the default react-select v2 componet and adds classNames to the options
 * which  are then targeted within our functional tests. For more information @see https://react-select.com/components
 */

const DefaultOption = ({ children, ...props }) => {
    const isNewOption = props.data.__isNew__;

    const optionText = isNewOption ? children : (
        <EmphasizedText match={ props.selectProps.inputValue }>
            { children }
        </EmphasizedText>
    );

    return (
        components.Option && (
            <components.Option
                className={
                    classnames({
                        "react-select-menu-option": !isNewOption,
                        "react-select-menu-create": isNewOption
                    })
                }
                { ...props }
            >
                { optionText }
            </components.Option>
        )
    );
};

DefaultOption.propTypes = {
    children: PropTypes.node,
    data: PropTypes.shape({
        __isNew__: PropTypes.bool
    }).isRequired,
    selectProps: PropTypes.shape({
        inputValue: PropTypes.string
    })
};

export default DefaultOption;
