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
 * Copyright 2025 Wren Security.
 */
package org.forgerock.openam.core.rest;

import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.api.annotations.Action;
import org.forgerock.api.annotations.ApiError;
import org.forgerock.api.annotations.CollectionProvider;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.Parameter;
import org.forgerock.api.annotations.Query;
import org.forgerock.api.annotations.Schema;
import org.forgerock.api.enums.QueryType;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.util.promise.Promises.newResultPromise;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.rest.DescriptorUtils;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

@CollectionProvider(
        details = @Handler(
                title = "i18n:api-descriptor/UserGroupsResource#title",
                description = "i18n:api-descriptor/UserGroupsResource#description",
                mvccSupported = true,
                parameters = {@Parameter(
                        name = "user",
                        type = "string",
                        description = "i18n:api-descriptor/UserGroupsResource#pathparams.user"
                )},
                resourceSchema = @Schema(
                        schemaResource = "UserGroupsResource.schema.json"
                )
        )
)
public class UserGroupsResource {
    protected final ContextHelper contextHelper;
    private final Debug debug;

    @Inject
    public UserGroupsResource(ContextHelper contextHelper, @Named("frRest") Debug debug) {
        this.contextHelper = contextHelper;
        this.debug = debug;
    }

    @Query(
            operationDescription = @Operation(
            description = "i18n:api-descriptor/UserGroupsResource#query.description",
            errors = {@ApiError(
                    code = 500,
                    description = "i18n:api-descriptor/UserGroupsResource#error.500.description"
            )}
    ),
            type = QueryType.FILTER,
            queryableFields = {"*"}
    )
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request, QueryResourceHandler handler) {
        List<ResourceResponse> response = new ArrayList<>();

        try {
            for (AMIdentity group : getUsersGroups(context, getRealm(context))) {
                response.add(buildResourceResponse(group.getName(), getJson(group)));
            }
        } catch (SSOException | IdRepoException e) {
            debug.error("UserGroupsResource :: Query - Unable to communicate with the SMS.", e);
            return new InternalServerErrorException().asPromise();
        }

        QueryResponsePresentation.enableDeprecatedRemainingQueryResponse(request);
        return QueryResponsePresentation.perform(handler, request, response);
    }

    @Action(operationDescription = @Operation, name = "schema")
    public Promise<ActionResponse, ResourceException> schema(Context context, ActionRequest request) {
        return newResultPromise(
                newActionResponse(DescriptorUtils.fromResource("UserGroupsResource.schema.json",
                        getClass()).getSchema()));
    }

    @Action(operationDescription = @Operation, name = "updateMemberships",
            request = @Schema(schemaResource = "UserGroupsResource.schema.json"),
            response = @Schema(schemaResource = "UserGroupsResource.schema.json")
    )
    public Promise<ActionResponse, ResourceException> updateMembershipsAction(Context context, ActionRequest request) {
        String realm = getRealm(context);
        AMIdentity user = getUser(context, realm);
        JsonValue response = new JsonValue(new LinkedHashMap<>());

        try {
            Set<AMIdentity> currentGroups = getUsersGroups(context, realm);
            Set<AMIdentity> requestedGroups = getRequestedGroups(request, realm);
            Set<AMIdentity> groupsToRemove = new HashSet<>(currentGroups);
            groupsToRemove.removeAll(requestedGroups);

            for (AMIdentity group : groupsToRemove) {
                group.removeMember(user);
            }

            Set<AMIdentity> groupsToAdd = new HashSet<>(requestedGroups);
            groupsToAdd.removeAll(currentGroups);

            for (AMIdentity group : groupsToAdd) {
                group.addMember(user);
            }

            for (AMIdentity group : getUsersGroups(context, realm)) {
                response.put(group.getName(), getJson(group));
            }

            RestUtils.removeExpiredAdminPrivilegeForUser(user);
        } catch (SSOException | IdRepoException e) {
            debug.error("UserGroupsResource :: updateMemberships - Unable to communicate with the SMS.", e);
            return new InternalServerErrorException().asPromise();
        } catch (BadRequestException e) {
            return new BadRequestException(e.getMessage(), e).asPromise();
        }

        return newActionResponse(response).asPromise();
    }

    private Set<AMIdentity> getRequestedGroups(ActionRequest request, String realm) throws BadRequestException {
        Set<AMIdentity> response = new HashSet<>();

        for (String groupName : request.getContent().get("groups").asCollection(String.class)) {
            AMIdentity groupIdentity = IdUtils.getGroup(groupName, realm);
            if (groupIdentity == null) {
                throw new BadRequestException("Unknown group: " + groupName);
            }

            response.add(groupIdentity);
        }

        return response;
    }

    private ResourceResponse buildResourceResponse(String resourceId, JsonValue content) {
        return newResourceResponse(resourceId, String.valueOf(content.getObject().hashCode()), content);
    }

    private JsonValue getJson(AMIdentity group) {
        return json(object(field("groupname", group.getName())));
    }

    private Set<AMIdentity> getUsersGroups(Context context, String realm) throws IdRepoException, SSOException {
        AMIdentity identity = getUser(context, realm);
        return identity.getMemberships(IdType.GROUP);
    }

    private AMIdentity getUser(Context context, String realm) {
        String userName = contextHelper.getUserId(context);
        return IdUtils.getIdentity(userName, realm);
    }

    private String getRealm(Context context) {
        RealmContext realmContext = context.asContext(RealmContext.class);
        return realmContext.getRealm().asPath();
    }
}
