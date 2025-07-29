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
 * Portions copyright 2022 Wren Security
 */

package org.forgerock.openam.core.rest.sms.tree;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.resource.ResourcePath.resourcePath;

import java.util.Collections;

import org.forgerock.authz.filter.crest.api.CrestAuthorizationModule;
import org.wrensecurity.guava.common.base.Predicate;
import org.forgerock.json.resource.Router;
import org.forgerock.openam.forgerockrest.utils.MatchingResourcePath;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class SmsRouteTreeLeafTest {

    private SmsRouteTree routeTree;

    @BeforeClass
    public void setup() {
        SmsRouteTreeBuilder.SmsRouter router = new SmsRouteTreeBuilder.SmsRouter();
        Predicate<String> handlesFunction = new Predicate<String>() {
            public boolean apply(String serviceName) {
                return "SERVICE_NAME".equals(serviceName);
            }
        };

        routeTree = new SmsRouteTree(Collections.<MatchingResourcePath, CrestAuthorizationModule>emptyMap(), null, false,
                router, null, resourcePath(""), handlesFunction, null, false, null);
    }

    @DataProvider(name = "handlesFunction")
    private Object[][] getHandlesFunctionData() {
        return new Object[][]{
            {"SERVICE_NAME", routeTree},
            {"OTHER_SERVICE_NAME", null},
        };
    }

    @Test(dataProvider = "handlesFunction")
    public void handlesShouldReturnThisRouteTreeInstanceIfHandlesFunctionReturnsTrue(String serviceName,
            SmsRouteTree expectedRouteTree) {

        //When
        SmsRouteTree tree = routeTree.handles(serviceName);

        //Then
        assertThat(tree).isEqualTo(expectedRouteTree);
    }
}
