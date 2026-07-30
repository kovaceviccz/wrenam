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
 * Copyright 2026 Wren Security.
 */
package org.forgerock.openam.core.rest.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.test.assertj.AssertJPromiseAssert.assertThatPromise;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.Requests;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.query.QueryFilter;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class UserGroupsResourceV1Test {

    private Context context;

    private UserGroupsResourceV1 resource;

    @BeforeMethod
    public void setUp() {
        context = mock(Context.class);
        resource = new UserGroupsResourceV1(null, mock(ContextHelper.class));
    }

    @Test
    public void shouldReturnMembershipSchema() throws Exception {
        ActionResponse response = resource.schema().getOrThrowUninterruptibly();

        assertThat(response.getJsonContent().get("properties").get("groups").get("type").asString())
                .isEqualTo("array");
        assertThat(response.getJsonContent().get("required").asList(String.class)).containsExactly("groups");
    }

    @Test
    public void shouldRejectUnsupportedQueryFilter() {
        QueryRequest request = Requests.newQueryRequest("")
                .setQueryFilter(QueryFilter.equalTo(new JsonPointer("groupname"), "group-a"));

        assertThatPromise(resource.queryCollection(context, request, mock(QueryResourceHandler.class)))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    public void shouldRejectNonArrayMemberships() {
        ActionRequest request = Requests.newActionRequest("", "updateMemberships")
                .setContent(json(object(field("groups", "group-a"))));

        assertThatPromise(resource.updateMemberships(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    public void shouldRejectNonStringMemberships() {
        ActionRequest request = Requests.newActionRequest("", "updateMemberships")
                .setContent(json(object(field("groups", Arrays.asList("group-a", 42)))));

        assertThatPromise(resource.updateMemberships(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
    }

}
