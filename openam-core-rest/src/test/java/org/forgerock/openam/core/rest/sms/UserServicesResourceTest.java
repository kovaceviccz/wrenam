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
package org.forgerock.openam.core.rest.sms;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.test.assertj.AssertJPromiseAssert.assertThatPromise;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.Requests;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class UserServicesResourceTest {

    private Context context;

    private UserServiceProvider provider;

    private UserServicesResource resource;

    @BeforeMethod
    public void setUp() {
        context = mock(Context.class);
        ContextHelper contextHelper = mock(ContextHelper.class);
        provider = mock(UserServiceProvider.class);
        when(contextHelper.getUserId(context)).thenReturn("demo");
        resource = new UserServicesResource(contextHelper, provider);
    }

    @Test
    public void shouldRejectNonArrayServiceNames() {
        ActionRequest request = Requests.newActionRequest("", "unassignServices")
                .setContent(json(object(field("serviceNames", "session"))));

        assertThatPromise(resource.unassignServices(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    public void shouldRejectNonStringServiceNames() {
        ActionRequest request = Requests.newActionRequest("", "unassignServices")
                .setContent(json(object(field("serviceNames", Collections.singletonList(1)))));

        assertThatPromise(resource.unassignServices(context, request))
                .failedWithException()
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    public void shouldPassEveryRequestedServiceToTheProvider() throws Exception {
        when(provider.unassign(any(Context.class), eq("demo"), any()))
                .thenReturn(json(object(field("success", true))));
        ActionRequest request = Requests.newActionRequest("", "unassignServices")
                .setContent(json(object(field("serviceNames", Arrays.asList("session", "dashboard")))));

        resource.unassignServices(context, request).getOrThrowUninterruptibly();

        verify(provider).unassign(context, "demo", Arrays.asList("session", "dashboard"));
    }

}
