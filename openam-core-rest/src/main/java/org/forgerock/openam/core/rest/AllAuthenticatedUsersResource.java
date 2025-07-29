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
import com.iplanet.sso.SSOToken;
import com.sun.identity.delegation.DelegationException;
import com.sun.identity.delegation.DelegationManager;
import com.sun.identity.delegation.DelegationPrivilege;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.ServiceManager;
import org.forgerock.api.models.Schema;
import org.forgerock.api.models.TranslateJsonSchema;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.ActionResponse;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.json.resource.SingletonResourceProvider;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import javax.inject.Inject;
import javax.inject.Named;
import java.security.AccessController;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.forgerock.json.resource.Responses.newActionResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;
import static org.forgerock.util.promise.Promises.newResultPromise;

public class AllAuthenticatedUsersResource implements SingletonResourceProvider {
    private static final String BASE_DN = ServiceManager.getBaseDN();
    private static final String ALL_AUTH_USERS_GUID = "id=All Authenticated Users,ou=role," + BASE_DN;
    private static final String ALL_AUTH_USERS_ID = "allauthenticatedusers";
    private static final String ROOT_REALM = "/";
    private final Debug debug;

    @Inject
    public AllAuthenticatedUsersResource(@Named("frRest") Debug debug) {
        this.debug = debug;
    }

    public Promise<ActionResponse, ResourceException> actionInstance(Context context, ActionRequest request) {
        String action = request.getAction();
        if ("schema".equalsIgnoreCase(action)) {
            JsonValue privileges = json(object());
            Set<String> allPrivilegeNames;
            try {
                allPrivilegeNames = getConfiguredPrivilegeNames();
            } catch (SSOException | DelegationException e) {
                debug.error("::AllAuthenticatedUsersResource:: {} on create schema", e);
                allPrivilegeNames = Collections.emptySet();
            }
            AtomicInteger propertyOrder = new AtomicInteger(1000);
            for (String privilegeName : allPrivilegeNames) {
                JsonValue privilege = json(
                        object(
                                field("title", "i18n:api-descriptor/IdentityResourceV4#groups.schema."
                                        + privilegeName + ".title"),
                                field("description", "i18n:api-descriptor/IdentityResourceV4#groups.schema."
                                        + privilegeName + ".description"),
                                field("propertyOrder", propertyOrder.getAndAdd(1000)),
                                field("type", "boolean"),
                                field("required", false),
                                field("exampleValue", ""))
                );
                privileges.add(privilegeName, privilege);
            }
            JsonValue schemaJson = json(
                    object(
                            field("type", "object"),
                            field(
                                    "properties",
                                    object(
                                            field(
                                                    "privileges",
                                                    object(
                                                            field("type", "object"),
                                                            field("title", "i18n:api-descriptor/IdentityResourceV4#groups.schema.section.privileges"),
                                                            field("propertyOrder", 1),
                                                            field("properties", privileges))
                                            ))
                            ))
            );
            JsonValue schema = Schema
                    .newBuilder()
                    .schema(schemaJson.as(new TranslateJsonSchema(getClass().getClassLoader())))
                    .build()
                    .getSchema();
            return newResultPromise(newActionResponse(schema));
        } else {
            return new NotSupportedException("The action '" + action + "' is not supported").asPromise();
        }
    }

    @Override
    public Promise<ResourceResponse, ResourceException> patchInstance(Context context, PatchRequest patchRequest) {
        return RestUtils.generateUnsupportedOperation();
    }

    public Promise<ResourceResponse, ResourceException> readInstance(Context context, ReadRequest request) {
        try {
            SSOToken adminSSOToken = getAdminSsoToken();
            String realm = RealmContext.getRealm(context).asPath();
            DelegationManager mgr = new DelegationManager(adminSSOToken, realm);
            Set<DelegationPrivilege> privileges = mgr.getPrivileges(ALL_AUTH_USERS_GUID);
            JsonValue result = createPrivilegesJson(privileges);
            String revision = String.valueOf(result.getObject().hashCode());
            return newResourceResponse(ALL_AUTH_USERS_ID, revision, result).asPromise();
        } catch (DelegationException | SSOException e) {
            debug.error("::AllAuthenticatedUsersResource:: {} on Read", e);
            return new InternalServerErrorException(e.getMessage(), e).asPromise();
        }
    }

    public Promise<ResourceResponse, ResourceException> updateInstance(Context context, UpdateRequest request) {
        try {
            Map<String, Object> requestedPrivileges = request
                    .getContent()
                    .get("privileges")
                    .defaultTo(Collections.emptyMap())
                    .asMap();
            SSOToken adminSSOToken = getAdminSsoToken();
            String realm = RealmContext.getRealm(context).asPath();
            DelegationManager mgr = new DelegationManager(adminSSOToken, realm);
            Set<String> allPrivilegeNames = getConfiguredPrivilegeNames();
            for (String privilegeName : requestedPrivileges.keySet()) {
                if (!allPrivilegeNames.contains(privilegeName)) {
                    throw new BadRequestException("Unknown privilege: " + privilegeName);
                }
            }

            Set<DelegationPrivilege> existingPrivileges = mgr.getPrivileges(ALL_AUTH_USERS_GUID);
            for (String privilegeName : requestedPrivileges.keySet()) {
                boolean privilegeRequested = (Boolean) requestedPrivileges.get(privilegeName);
                DelegationPrivilege existingPrivilege = getPrivilege(existingPrivileges, privilegeName);
                if (existingPrivilege != null) {
                    Set<String> subjectsForPrivilege = existingPrivilege.getSubjects();
                    if (privilegeRequested) {
                        if (!subjectsForPrivilege.contains(ALL_AUTH_USERS_GUID)) {
                            subjectsForPrivilege.add(ALL_AUTH_USERS_GUID);
                            existingPrivilege.setSubjects(subjectsForPrivilege);
                            mgr.addPrivilege(existingPrivilege);
                        }
                    } else if (subjectsForPrivilege.contains(ALL_AUTH_USERS_GUID)) {
                        subjectsForPrivilege.remove(ALL_AUTH_USERS_GUID);
                        existingPrivilege.setSubjects(subjectsForPrivilege);
                        mgr.addPrivilege(existingPrivilege);
                    }
                } else if (privilegeRequested) {
                    Set<String> subjects = new HashSet<>();
                    subjects.add(ALL_AUTH_USERS_GUID);
                    DelegationPrivilege newPrivilege = new DelegationPrivilege(privilegeName, subjects, realm);
                    mgr.addPrivilege(newPrivilege);
                }
            }

            JsonValue result = createPrivilegesJson(mgr.getPrivileges(ALL_AUTH_USERS_GUID));
            String revision = String.valueOf(result.getObject().hashCode());
            return newResourceResponse(ALL_AUTH_USERS_ID, revision, result).asPromise();
        } catch (ResourceException e) {
            debug.warning("::AllAuthenticatedUsersResource:: {} on Update", e.getClass().getSimpleName(), e);
            return e.asPromise();
        } catch (DelegationException | SSOException e) {
            debug.error("::AllAuthenticatedUsersResource:: {} on Update", e);
            return new InternalServerErrorException(e.getMessage(), e).asPromise();
        }
    }

    /**
     * Gets an administrative SSOToken for privileged operations.
     */
    private SSOToken getAdminSsoToken() {
        return AccessController.doPrivileged(AdminTokenAction.getInstance());
    }

    /**
     * Gets names of all privileges configured in the root realm.
     */
    private Set<String> getConfiguredPrivilegeNames() throws SSOException, DelegationException {
        SSOToken adminSSOToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
        DelegationManager mgr = new DelegationManager(adminSSOToken, ROOT_REALM);
        return mgr.getConfiguredPrivilegeNames();
    }

    /**
     * Converts a set of {@link DelegationPrivilege} into expected JSON structure.
     *
     * @param privileges applied privileges
     */
    private JsonValue createPrivilegesJson(Set<DelegationPrivilege> privileges)
            throws DelegationException, SSOException {
        Map<String, Boolean> privilegeResults = new HashMap<>();
        Set<String> appliedPrivileges = privileges
                .stream()
                .map(DelegationPrivilege::getName)
                .collect(Collectors.toSet());
        for (String privilege : getConfiguredPrivilegeNames()) {
            if (appliedPrivileges.contains(privilege)) {
                privilegeResults.put(privilege, true);
            } else {
                privilegeResults.put(privilege, false);
            }
        }
        return json(object(field("privileges", privilegeResults)));
    }

    /**
     * Gets a privilege with the specified name in the supplied set.
     *
     * @param existingPrivileges set of {@link DelegationPrivilege}
     * @param privilegeName privilege name to get
     *
     * @return the privilege, or {@code null} if not present
     */
    private DelegationPrivilege getPrivilege(Set<DelegationPrivilege> existingPrivileges, String privilegeName) {
        return existingPrivileges.stream()
                .filter(privilege -> privilege.getName().equals(privilegeName))
                .findFirst()
                .orElse(null);
    }
}
