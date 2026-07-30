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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.openam.core.rest.identity.IdentityRestUtils.getIdentityServicesAttributes;

import com.iplanet.sso.SSOToken;
import com.sun.identity.idsvcs.AccessDenied;
import com.sun.identity.idsvcs.IdServicesException;
import com.sun.identity.idsvcs.IdentityDetails;
import com.sun.identity.idsvcs.ListWrapper;
import com.sun.identity.idsvcs.NeedMoreCredentials;
import com.sun.identity.idsvcs.ObjectNotFound;
import com.sun.identity.idsvcs.TokenExpired;
import com.sun.identity.idsvcs.opensso.IdentityServicesImpl;
import com.sun.identity.shared.debug.Debug;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import org.forgerock.api.annotations.Action;
import org.forgerock.api.annotations.CollectionProvider;
import org.forgerock.api.annotations.Handler;
import org.forgerock.api.annotations.Operation;
import org.forgerock.api.annotations.Query;
import org.forgerock.api.annotations.Schema;
import org.forgerock.api.enums.QueryType;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.PermanentException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.openam.forgerockrest.utils.ServerContextUtils;
import org.forgerock.openam.rest.DescriptorUtils;
import org.forgerock.openam.rest.RestConstants;
import org.forgerock.openam.rest.query.QueryResponsePresentation;
import org.forgerock.openam.rest.resource.ContextHelper;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

/**
 * Replaces the realm-scoped group memberships of one AM user.
 *
 * Every requested group is validated before the replacement starts, so an invalid group cannot leave a partially
 * updated membership set. A present empty group array deliberately removes every current membership.
 */
@CollectionProvider(details = @Handler(mvccSupported = false,
        resourceSchema = @Schema(schemaResource = "UserGroupsResourceV1.schema.json")))
public final class UserGroupsResourceV1 {

    private static final String GROUPS_PROP = "groups";

    private static final String GROUP_NAME_PROP = "groupname";

    private static final String UPDATE_MEMBERSHIPS_ACTION = "updateMemberships";

    private static final Debug DEBUG = Debug.getInstance("frRest");

    private final IdentityServicesImpl identityServices;

    private final ContextHelper contextHelper;

    @Inject
    public UserGroupsResourceV1(IdentityServicesImpl identityServices, ContextHelper contextHelper) {
        this.identityServices = identityServices;
        this.contextHelper = contextHelper;
    }

    @Action(name = RestConstants.SCHEMA, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> schema() {
        return newActionResponse(DescriptorUtils.fromResource(
                "UserGroupsResourceV1.schema.json", getClass()).getSchema().copy()).asPromise();
    }

    @Action(name = UPDATE_MEMBERSHIPS_ACTION, operationDescription = @Operation)
    public Promise<ActionResponse, ResourceException> updateMemberships(Context context, ActionRequest request) {
        List<String> requestedGroups;
        try {
            JsonValue groups = request.getContent().get(GROUPS_PROP);
            if (!groups.isList()) {
                return new BadRequestException("The groups property must be an array").asPromise();
            }
            requestedGroups = new ArrayList<>(new LinkedHashSet<>(groups.asList(String.class)));
            if (requestedGroups.stream().anyMatch(group -> group == null || group.isEmpty())) {
                return new BadRequestException("Group identifiers must not be empty").asPromise();
            }
        } catch (JsonValueException e) {
            return new BadRequestException("The groups property must contain only group identifiers").asPromise();
        }

        String realm = contextHelper.getRealm(context);
        String user = contextHelper.getUserId(context);
        SSOToken token = ServerContextUtils.getTokenFromContext(context, DEBUG);

        try {
            IdentityDetails details = identityServices.read(user,
                    getIdentityServicesAttributes(realm, IdentityRestUtils.USER_TYPE), token);
            if (details == null) {
                return new NotFoundException("Identity does not exist: " + user).asPromise();
            }
        } catch (ObjectNotFound e) {
            return new NotFoundException("Identity does not exist: " + user).asPromise();
        } catch (NeedMoreCredentials | AccessDenied e) {
            return new ForbiddenException("Token is not authorized").asPromise();
        } catch (TokenExpired e) {
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (IdServicesException e) {
            DEBUG.warning("Unable to read identity {}", user, e);
            return new InternalServerErrorException("Unable to read identity: " + user).asPromise();
        }

        for (String group : requestedGroups) {
            try {
                IdentityDetails details = identityServices.read(group,
                        getIdentityServicesAttributes(realm, IdentityRestUtils.GROUP_TYPE), token);
                if (details == null) {
                    return new BadRequestException("Group does not exist: " + group).asPromise();
                }
            } catch (ObjectNotFound e) {
                return new BadRequestException("Group does not exist: " + group).asPromise();
            } catch (NeedMoreCredentials | AccessDenied e) {
                return new ForbiddenException("Token is not authorized").asPromise();
            } catch (TokenExpired e) {
                return new PermanentException(401, "Unauthorized", null).asPromise();
            } catch (IdServicesException e) {
                DEBUG.warning("Unable to read identity {}", group, e);
                return new InternalServerErrorException("Unable to read identity: " + group).asPromise();
            }
        }

        IdentityDetails update = new IdentityDetails();
        update.setName(user);
        update.setType(IdentityRestUtils.USER_TYPE);
        update.setRealm(realm);
        update.setGroupList(new ListWrapper(requestedGroups.toArray(new String[0])));

        try {
            identityServices.update(update, token);
            IdentityDetails updatedUser = identityServices.read(user,
                    getIdentityServicesAttributes(realm, IdentityRestUtils.USER_TYPE), token);
            if (updatedUser == null) {
                return new NotFoundException("Identity does not exist: " + user).asPromise();
            }
            List<String> groupNames = new ArrayList<>();
            ListWrapper groupList = updatedUser.getGroupList();
            if (groupList != null && groupList.getElements() != null) {
                groupNames.addAll(Arrays.asList(groupList.getElements()));
            }
            return newActionResponse(json(object(
                    field(GROUPS_PROP, groupNames)
            ))).asPromise();
        } catch (ObjectNotFound e) {
            return new NotFoundException("Identity does not exist: " + user).asPromise();
        } catch (NeedMoreCredentials | AccessDenied e) {
            return new ForbiddenException("Token is not authorized").asPromise();
        } catch (TokenExpired e) {
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (IdServicesException e) {
            DEBUG.warning("Unable to read identity {}", user, e);
            return new InternalServerErrorException("Unable to read identity: " + user).asPromise();
        } catch (ResourceException e) {
            return e.asPromise();
        }
    }

    @Query(operationDescription = @Operation, type = QueryType.FILTER)
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        if (request.getQueryFilter() == null || !"true".equals(request.getQueryFilter().toString())) {
            return new BadRequestException("Only _queryFilter=true is supported").asPromise();
        }

        String realm = contextHelper.getRealm(context);
        String user = contextHelper.getUserId(context);
        SSOToken token = ServerContextUtils.getTokenFromContext(context, DEBUG);

        try {
            IdentityDetails details = identityServices.read(user,
                    getIdentityServicesAttributes(realm, IdentityRestUtils.USER_TYPE), token);
            if (details == null) {
                return new NotFoundException("Identity does not exist: " + user).asPromise();
            }
            List<String> groupNames = new ArrayList<>();
            ListWrapper groupList = details.getGroupList();
            if (groupList != null && groupList.getElements() != null) {
                groupNames.addAll(Arrays.asList(groupList.getElements()));
            }
            List<ResourceResponse> resources = new ArrayList<>();
            for (String groupName : groupNames) {
                JsonValue content = json(object(field(GROUP_NAME_PROP, groupName)));
                resources.add(newResourceResponse(groupName, Integer.toString(content.hashCode()), content));
            }
            return QueryResponsePresentation.perform(handler, request, resources);
        } catch (ObjectNotFound e) {
            return new NotFoundException("Identity does not exist: " + user).asPromise();
        } catch (NeedMoreCredentials | AccessDenied e) {
            return new ForbiddenException("Token is not authorized").asPromise();
        } catch (TokenExpired e) {
            return new PermanentException(401, "Unauthorized", null).asPromise();
        } catch (IdServicesException e) {
            DEBUG.warning("Unable to read identity {}", user, e);
            return new InternalServerErrorException("Unable to read identity: " + user).asPromise();
        }
    }

}
