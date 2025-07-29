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
package org.forgerock.openam.rest.authz;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.authz.filter.api.AuthorizationResult;
import org.forgerock.authz.filter.crest.api.CrestAuthorizationModule;
import org.forgerock.json.resource.ActionRequest;
import org.forgerock.json.resource.CreateRequest;
import org.forgerock.json.resource.DeleteRequest;
import org.forgerock.json.resource.PatchRequest;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.ReadRequest;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.UpdateRequest;
import org.forgerock.openam.rest.RestUtils;
import org.forgerock.openam.rest.resource.SSOTokenContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

import javax.inject.Inject;
import javax.inject.Named;

import static com.sun.identity.shared.Constants.UNIVERSAL_IDENTIFIER;
import static org.forgerock.util.promise.Promises.newResultPromise;

public class AdminOrDelegatedAdminAuthzModule implements CrestAuthorizationModule {
    private static final String NAME = "AdminOrDelegatedAdminFilter";
    private final Debug debug;

    @Inject
    public AdminOrDelegatedAdminAuthzModule(@Named("frRest") Debug debug) {
        this.debug = debug;
    }

    public String getName() {
        return NAME;
    }

    public Promise<AuthorizationResult, ResourceException> authorizeCreate(Context context, CreateRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizeRead(Context context, ReadRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizeUpdate(Context context, UpdateRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizeDelete(Context context, DeleteRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizePatch(Context context, PatchRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizeAction(Context context, ActionRequest request) {
        return authorize(context);
    }

    public Promise<AuthorizationResult, ResourceException> authorizeQuery(Context context, QueryRequest request) {
        return authorize(context);
    }

    private Promise<AuthorizationResult, ResourceException> authorize(Context context) {
        try {
            String userId = getUserId(context);
            if (RestUtils.isAdmin(context)) {
                debug.message("AdminOrDelegatedAdminAuthzModule :: User, {} accepted as Administrator or Delegated Administrator.", userId);
                return newResultPromise(AuthorizationResult.accessPermitted());
            } else {
                debug.message("AdminOrDelegatedAdminAuthzModule :: Restricted access to {}", userId);
                return newResultPromise(AuthorizationResult.accessDenied("User is not an administrator or Delegated Administrator."));
            }
        } catch (SSOException e) {
            debug.message("AdminOrDelegatedAdminAuthzModule :: Unable to authorize user using SSO Token.");
            return newResultPromise(AuthorizationResult.accessDenied("Not authorized."));
        }
    }

    private String getUserId(Context context) throws SSOException {
        SSOTokenContext tokenContext = context.asContext(SSOTokenContext.class);
        SSOToken token = tokenContext.getCallerSSOToken();
        return token == null ? null : token.getProperty(UNIVERSAL_IDENTIFIER);
    }
}
