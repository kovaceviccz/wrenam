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
 * Copyright 2025 Wren Security. All rights reserved.
 */
package org.forgerock.openam.core.rest;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.util.promise.Promises.newResultPromise;

import com.iplanet.dpro.session.service.SessionService;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationManager;
import com.sun.identity.delegation.DelegationPrivilege;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.idsvcs.AccessDenied;
import com.sun.identity.idsvcs.Attribute;
import com.sun.identity.idsvcs.IdServicesException;
import com.sun.identity.idsvcs.IdentityDetails;
import com.sun.identity.idsvcs.ListWrapper;
import com.sun.identity.idsvcs.NeedMoreCredentials;
import com.sun.identity.idsvcs.ObjectNotFound;
import com.sun.identity.idsvcs.TokenExpired;
import com.sun.identity.idsvcs.opensso.IdentityServicesImpl;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.forgerock.api.models.Schema;
import org.forgerock.api.models.TranslateJsonSchema;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.CollectionResourceProvider;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.PermanentException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.forgerockrest.utils.MailServerLoader;
import org.forgerock.openam.forgerockrest.utils.PrincipalRestUtils;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.services.RestSecurityProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.sm.config.ConsoleConfigHandler;
import org.forgerock.openam.utils.Config;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

public final class IdentityResourceV4 implements CollectionResourceProvider {

    public static final String USER_TYPE = "user";

    public static final String GROUP_TYPE = "group";

    private static final Debug debug = Debug.getInstance("frRest");

    private final String objectType;

    private final IdentityServicesImpl identityServices;

    private final IdentityResourceV3 identityResourceV3;

    private final Config<SessionService> sessionService;

    /**
     * Construct a new identity resource.
     */
    public IdentityResourceV4(String objectType, MailServerLoader mailServerLoader,
            IdentityServicesImpl identityServices, CoreWrapper coreWrapper, RestSecurityProvider restSecurityProvider,
            ConsoleConfigHandler configHandler, BaseURLProviderFactory baseURLProviderFactory,
            Set<String> patchableAttributes, Set<UiRolePredicate> uiRolePredicates,
            Config<SessionService> sessionService) {
        this.objectType = objectType;
        this.identityServices = identityServices;
        this.sessionService = sessionService;
        this.identityResourceV3 = new IdentityResourceV3(objectType, mailServerLoader, identityServices, coreWrapper,
                restSecurityProvider, configHandler, baseURLProviderFactory, patchableAttributes, uiRolePredicates);
    }

    @Override
    public Promise<ResourceResponse, ResourceException> createInstance(Context context, CreateRequest request) {
        return identityResourceV3.createInstance(context, request).then(resourceResponse -> {
            if (GROUP_TYPE.equals(objectType)) {
                try {
                    SSOToken adminSSOToken = getAdminSSOToken();
                    String realm = getRealm(context);
                    String resourceId = resourceResponse.getContent().get("universalid").get(0).asString();

                    DelegationManager mgr = new DelegationManager(adminSSOToken, realm);

                    IdentityDetails identityDetails = identityServices.read(
                            resourceId,
                            IdentityRestUtils.getIdentityServicesAttributes(realm, GROUP_TYPE),
                            adminSSOToken);

                    String universalId = getUniversalId(identityDetails);
                    AMIdentity amIdentity = new AMIdentity(adminSSOToken, universalId);

                    return buildResourceResponse(resourceId,
                            groupIdentityToJsonValue(
                                amIdentity,
                                mgr.getPrivileges(universalId),
                                mgr.getConfiguredPrivilegeNames()));
                } catch (SSOException | DelegationException | IdServicesException | IdRepoException e) {
                    debug.error("IdentityResource.createInstance() :: failed.", e);
                    return resourceResponse;
                }
            } else {
                return resourceResponse;
            }
        });
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readInstance(Context context, String resourceId,
            ReadRequest request) {
        if (GROUP_TYPE.equals(objectType)) {
            try {
                SSOToken ssoToken = IdentityRestUtils.getSSOToken(
                        RestUtils.getCookieFromServerContext(context));
                String realm = getRealm(context);
                IdentityDetails identityDetails = identityServices.read(resourceId,
                        IdentityRestUtils.getIdentityServicesAttributes(realm, GROUP_TYPE), ssoToken);
                String universalId = getUniversalId(identityDetails);
                AMIdentity amIdentity = new AMIdentity(ssoToken, universalId);
                String principalName = PrincipalRestUtils.getPrincipalNameFromServerContext(context);
                if (debug.messageEnabled()) {
                    debug.message(
                            "IdentityResource.readInstance :: READ of resourceId={} in realm={}"
                                + " performed by principalName={}",
                            resourceId, realm, principalName);
                }

                SSOToken adminSSOToken = getAdminSSOToken();
                DelegationManager mgr = new DelegationManager(adminSSOToken, realm);
                Set<DelegationPrivilege> groupPrivileges = mgr.getPrivileges(universalId);
                return newResultPromise(
                        buildResourceResponse(resourceId, groupIdentityToJsonValue(
                            amIdentity,
                            groupPrivileges,
                            mgr.getConfiguredPrivilegeNames())));
            } catch (NeedMoreCredentials e) {
                debug.error(
                        "IdentityResource.readInstance() :: Cannot READ resourceId={} : User does not have enough privileges.",
                        resourceId, e);
                return new ForbiddenException("User does not have enough privileges.", e).asPromise();
            } catch (ObjectNotFound e) {
                debug.error("IdentityResource.readInstance() :: Cannot READ resourceId={}"
                        + " : Resource cannot be found.", resourceId, e);
                return new NotFoundException("Resource cannot be found.", e).asPromise();
            } catch (TokenExpired e) {
                debug.error("IdentityResource.readInstance() :: Cannot READ resourceId={}"
                        + " : Unauthorized", resourceId, e);
                return new PermanentException(401, "Unauthorized", null).asPromise();
            } catch (AccessDenied e) {
                debug.error("IdentityResource.readInstance() :: Cannot READ resourceId={}"
                        + " : Access denied", resourceId, e);
                return new ForbiddenException(e.getMessage(), e).asPromise();
            } catch (Exception e) {
                debug.error("IdentityResource.readInstance() :: Cannot READ resourceId={}", resourceId, e);
                return new BadRequestException(e.getMessage(), e).asPromise();
            }
        } else {
            return identityResourceV3.readInstance(context, resourceId, request);
        }
    }

    @Override
    public Promise<QueryResponse, ResourceException> queryCollection(Context context, QueryRequest request,
            QueryResourceHandler handler) {
        return identityResourceV3.queryCollection(context, request, handler);
    }

    @Override
    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, String resourceId,
            UpdateRequest request) {
        if (GROUP_TYPE.equals(objectType)) {
            try {
                SSOToken adminSSOToken = getAdminSSOToken();
                String realm = getRealm(context);

                DelegationManager mgr = new DelegationManager(adminSSOToken, realm);
                Set<String> allPrivilegeNames = mgr.getConfiguredPrivilegeNames();
                Map<String, Object> requestedPrivileges = request.getContent().get("privileges")
                        .defaultTo(Collections.emptyMap()).asMap();
                for (String privilegeName : requestedPrivileges.keySet()) {
                    if (!allPrivilegeNames.contains(privilegeName)) {
                        throw new BadRequestException("Unknown privilege: " + privilegeName);
                    }
                }

                IdentityDetails groupDetails = getExistingGroupDetails(context, resourceId, realm);
                IdentityDetails updatedGroupDetails = getUpdatedGroupDetails(resourceId, request, groupDetails);
                identityServices.update(updatedGroupDetails,
                        IdentityRestUtils.getSSOToken(RestUtils.getCookieFromServerContext(context)));
                removeAdminPrivilegeForUsers(groupDetails, updatedGroupDetails, realm);

                String groupUid = getUniversalId(groupDetails);
                Set<DelegationPrivilege> existingPrivileges = mgr.getPrivileges(groupUid);

                for (String privilegeName : requestedPrivileges.keySet()) {
                    boolean privilegeValue = (Boolean) requestedPrivileges.get(privilegeName);
                    DelegationPrivilege existingPrivilege = getPrivilege(existingPrivileges, privilegeName);

                    if (existingPrivilege != null) {
                        Set<String> subjects = existingPrivilege.getSubjects();
                        if (privilegeValue && !subjects.contains(groupUid)) {
                            subjects.add(groupUid);
                            mgr.addPrivilege(existingPrivilege);
                        } else if (!privilegeValue && subjects.contains(groupUid)) {
                            subjects.remove(groupUid);
                            mgr.addPrivilege(existingPrivilege);
                        }
                    } else if (privilegeValue) {
                        Set<String> subjects = new HashSet<>();
                        subjects.add(groupUid);
                        DelegationPrivilege newDp = new DelegationPrivilege(privilegeName, subjects, realm);
                        mgr.addPrivilege(newDp);
                    }
                }

                AMIdentity updatedAMIdentity = new AMIdentity(adminSSOToken, groupUid);
                return newResultPromise(buildResourceResponse(resourceId, groupIdentityToJsonValue(
                        updatedAMIdentity,
                        mgr.getPrivileges(groupUid),
                        allPrivilegeNames)));
            } catch (IdServicesException | DelegationException | IdRepoException | SSOException e) {
                debug.error("IdentityResource.updateInstance() :: failed.", e);
                return new InternalServerErrorException(e.getMessage(), e).asPromise();
            } catch (ResourceException e) {
                return e.asPromise();
            }
        } else {
            return identityResourceV3.updateInstance(context, resourceId, request);
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, String resourceId,
            PatchRequest request) {
        return identityResourceV3.patchInstance(context, resourceId, request);
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionCollection(Context context, ActionRequest request) {
        final String action = request.getAction();
        if ("schema".equalsIgnoreCase(action) && GROUP_TYPE.equalsIgnoreCase(objectType)) {
            String realm = context.asContext(RealmContext.class).getRealm().asPath();
            JsonValue schemaJson = JsonValueBuilder.fromResource(
                    getClass(), "IdentityResourceV4.groups.schema.json");

            try {
                int propertyOrder = 1000;
                JsonValue privileges = json(
                        object(
                            field("type", "object"),
                            field("title", "i18n:api-descriptor/IdentityResourceV4#groups.schema.section.privileges"),
                            field("propertyOrder", "2")));
                for (String privilegeName : getPrivilegeNames(realm)) {
                    JsonValue privilege = json(
                            object(
                                field("title",
                                    "i18n:api-descriptor/IdentityResourceV4#groups.schema." + privilegeName + ".title"),
                                field("description", "i18n:api-descriptor/IdentityResourceV4#groups.schema."
                                    + privilegeName + ".description"),
                                field("propertyOrder", propertyOrder),
                                field("type", "boolean"),
                                field("required", false),
                                field("exampleValue", "")));
                    privileges.putPermissive(
                            new JsonPointer("properties/" + privilegeName), privilege);
                    propertyOrder += 1000;
                }
                schemaJson.putPermissive(new JsonPointer("properties/privileges"), privileges);
                schemaJson = Schema.newBuilder()
                        .schema(schemaJson.as(new TranslateJsonSchema(
                            getClass().getClassLoader()))).build()
                        .getSchema();
            } catch (SSOException | DelegationException e) {
                return new InternalServerErrorException("Failed to retrieve privilege names", e).asPromise();
            }

            return newResultPromise(newActionResponse(schemaJson));
        }
        return identityResourceV3.actionCollection(context, request);
    }

    @Override
    public Promise<ActionResponse, ResourceException> actionInstance(Context context, String resourceId,
            ActionRequest request) {
        return identityResourceV3.actionInstance(context, resourceId, request);
    }

    @Override
    public Promise<ResourceResponse, ResourceException> deleteInstance(Context context, String resourceId,
            DeleteRequest request) {
        if (USER_TYPE.equals(objectType)) {
            AMIdentity identity = IdUtils.getIdentity(resourceId, getRealm(context));
            if (identity == null) {
                return new NotFoundException("Resource cannot be found.").asPromise();
            }
            if (sessionService.get().isSuperUser(identity.getUniversalId())) {
                return new ForbiddenException("It's forbidden to delete " + resourceId).asPromise();
            }
        }
        return identityResourceV3.deleteInstance(context, resourceId, request);
    }

    /**
     * Return every delegation privilege name configured in the supplied realm.
     *
     * @param realm the realm in path format
     * @return An immutable set of privilege names
     * @throws SSOException        if the admin SSO token cannot be obtained or is invalid
     * @throws DelegationException If the delegation framework fails to read the privileges
     */
    private Set<String> getPrivilegeNames(String realm) throws SSOException, DelegationException {
        SSOToken adminSSOToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        DelegationManager mgr = new DelegationManager(adminSSOToken, realm);
        return mgr.getConfiguredPrivilegeNames();
    }

    /**
     * Extract the first universalid attribute value from an {@link IdentityDetails} instance.
     */
    private String getUniversalId(IdentityDetails identityDetails) {
        return Arrays.stream(identityDetails.getAttributes())
                .filter(attribute -> "universalid".equals(attribute.getName()))
                .map(Attribute::getValues)
                .filter(values -> values != null && values.length > 0)
                .map(values -> values[0])
                .findFirst()
                .orElse(null);
    }

    /**
     * Get the current state of a group from the IdM layer.
     */
    private IdentityDetails getExistingGroupDetails(Context context, String resourceId, String realm)
            throws IdServicesException, SSOException {
        return identityServices.read(resourceId,
                IdentityRestUtils.getIdentityServicesAttributes(realm,GROUP_TYPE),
                IdentityRestUtils.getSSOToken(RestUtils.getCookieFromServerContext(context)));
    }

    /**
     * Get an {@link IdentityDetails} object that represents the desired post‑update state of a group, based on the
     * supplied {@link UpdateRequest}. Only attributes relevant to membership changes are modified here; other
     * attributes are copied verbatim from the existing group details.
     */
    private IdentityDetails getUpdatedGroupDetails(String resourceId, UpdateRequest request,
            IdentityDetails groupDetails) throws BadRequestException {
        IdentityDetails newGroupDetails = new IdentityDetails();
        List<String> newMemberList = new ArrayList<>();
        JsonValue memberList = request.getContent().get(new JsonPointer("members/uniqueMember"));
        if (!memberList.isNull() && memberList.isList()) {
            newMemberList = memberList.asList(String.class);
        }
        if (newMemberList.isEmpty()) {
            Map<String, Set<String>> membersMap = new HashMap<>();
            membersMap.put("uniqueMember", new HashSet<>());
            newGroupDetails.setAttributes(IdentityServicesImpl.asAttributeArray(membersMap));
        }
        newGroupDetails.setMemberList(new ListWrapper(newMemberList.toArray(new String[0])));
        newGroupDetails.setName(resourceId);
        newGroupDetails.setRealm(groupDetails.getRealm());
        newGroupDetails.setRoleList(groupDetails.getRoleList());
        newGroupDetails.setType(groupDetails.getType());
        return newGroupDetails;
    }

    /**
     * Remove delegated “admin” privileges for users that were *removed* from a group update operation. The method
     * compares the membership lists *before* and *after* the change, calculates which users were dropped, and then
     * ensures any expired admin privilege markers are cleared.
     */
    private void removeAdminPrivilegeForUsers(IdentityDetails before, IdentityDetails after, String realm)
            throws IdRepoException, SSOException {
        if (before.getMemberList() == null || after.getMemberList() == null) {
            return;
        }
        Set<String> removedUsers = new HashSet<>(Arrays.asList(before.getMemberList().getElements()));
        Arrays.asList(after.getMemberList().getElements()).forEach(removedUsers::remove);
        for (String username : removedUsers) {
            RestUtils.removeExpiredAdminPrivilegeForUser(IdUtils.getIdentity(username, realm));
        }
    }

    /**
     * Get an administrative SSOToken for privileged operations.
     */
    private SSOToken getAdminSSOToken() {
        return AccessController.doPrivileged(AdminTokenAction.getInstance());
    }

    private String getRealm(Context ctx) {
        return ctx.asContext(RealmContext.class).getRealm().asPath();
    }

    /**
     * Get a privilege with the specified name in the supplied set.
     */
    private DelegationPrivilege getPrivilege(Set<DelegationPrivilege> existingPrivileges, String privilegeName) {
        return existingPrivileges.stream()
                .filter(privilege -> privilege.getName().equals(privilegeName))
                .findFirst()
                .orElse(null);
    }

    /**
     * Create a {@link ResourceResponse} with an opaque revision (version) derived from the supplied JSON content’s
     * hash code.
     */
    private ResourceResponse buildResourceResponse(String resourceId, JsonValue content) {
        return newResourceResponse(resourceId, String.valueOf(content.getObject().hashCode()), content);
    }

    /**
     * Convert an {@link AMIdentity} representing a *group* into the JSON structure expected by the V4 REST API,
     * enriching it with its members and computed privilege flags.
     */
    private JsonValue groupIdentityToJsonValue(AMIdentity groupIdentity, Set<DelegationPrivilege> requestedPrivileges,
            Set<String> allPrivilegeNames) {
        JsonValue result = new JsonValue(new LinkedHashMap<>());
        try {
            result.put("username", groupIdentity.getName());
            result.put("realm",
                    new CoreWrapper().convertOrgNameToRealmName(groupIdentity.getRealm()));
            result.put("universalid", Collections.singletonList(groupIdentity.getUniversalId()));

            Set<AMIdentity> members = groupIdentity.getMembers(IdType.USER);
            List<String> uniqueMembers = members.stream()
                    .map(AMIdentity::getName)
                    .collect(Collectors.toList());
            result.add("members", json(object(field("uniqueMember", uniqueMembers))));

            Map<String, Set<String>> allAttrs = groupIdentity.getAttributes();
            allAttrs.entrySet().stream()
                    .filter(e -> !Set.of("uniqueMember", "member").contains(e.getKey()))
                    .forEach(e ->
                        result.put(e.getKey(), new ArrayList<>(e.getValue())));

            JsonValue privilegesJson = json(object());
            allPrivilegeNames.forEach(n -> privilegesJson.put(n, false));
            requestedPrivileges.forEach(dp -> privilegesJson.put(dp.getName(), true));
            result.add("privileges", privilegesJson);
            return result;
        } catch (Exception e) {
            throw new JsonValueException(result, e.getMessage());
        }
    }

}
