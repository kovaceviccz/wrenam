/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security. All rights reserved.
 */
package org.wrensecurity.wrenam.authentication.modules.webauthn.impl;

import static com.sun.identity.idm.IdType.USER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.forgerock.util.query.QueryFilter.equalTo;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.sm.SMSException;
import jakarta.inject.Inject;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import org.forgerock.json.JsonPointer;
import org.forgerock.openam.utils.CrestQuery;
import org.forgerock.util.Reject;
import org.forgerock.util.query.QueryFilter;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnAccountRepository;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyError;
import org.wrensecurity.wrenam.authentication.modules.webauthn.core.WebAuthnCeremonyException;

/**
 * Resolve WebAuthn account identity data from AM identities.
 */
public class AmWebAuthnAccountRepository implements WebAuthnAccountRepository {

    private static final int NO_LIMIT = 0;

    private final WebAuthnServiceConfig serviceConfig;

    /**
     * Create an AM-backed WebAuthn account repository.
     *
     * @param serviceConfig WebAuthn service configuration
     */
    @Inject
    public AmWebAuthnAccountRepository(WebAuthnServiceConfig serviceConfig) {
        Reject.ifNull(serviceConfig);
        this.serviceConfig = serviceConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getUserHandle(String username, String realm) throws WebAuthnCeremonyException {
        Reject.ifNull(username, realm);
        AMIdentity identity = getIdentityByUsername(username, realm);
        String userHandle = getAttributeValue(
                identity, getUserHandleAttribute(realm, WebAuthnCeremonyError.WEBAUTHN_SERVICE_CONFIG_ERROR));
        if (userHandle == null || userHandle.isBlank()) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.MISSING_USER_ID_ATTRIBUTE);
        }
        return userHandle.getBytes(UTF_8);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getDisplayName(String username, String realm) throws WebAuthnCeremonyException {
        Reject.ifNull(username, realm);
        AMIdentity identity = getIdentityByUsername(username, realm);
        String displayName = getAttributeValue(identity, getUserDisplayNameAttribute(realm));
        return displayName == null || displayName.isBlank() ? username : displayName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> findUsernameByUserHandle(byte[] userHandle, String realm)
            throws WebAuthnCeremonyException {
        if (userHandle == null || userHandle.length == 0) {
            return Optional.empty();
        }
        Reject.ifNull(realm);
        String userHandleAttribute =
                getUserHandleAttribute(realm, WebAuthnCeremonyError.USER_ID_ATTR_LOOKUP_FAILED);
        QueryFilter<JsonPointer> queryFilter =
                equalTo(new JsonPointer(userHandleAttribute), new String(userHandle, UTF_8));
        return findIdentity(new CrestQuery(queryFilter), realm).map(AMIdentity::getName);
    }

    private String getUserHandleAttribute(String realm, WebAuthnCeremonyError error)
            throws WebAuthnCeremonyException {
        try {
            return serviceConfig.getUserIdAttribute(realm);
        } catch (SMSException | SSOException e) {
            throw new WebAuthnCeremonyException(error, e);
        }
    }

    private String getUserDisplayNameAttribute(String realm) throws WebAuthnCeremonyException {
        try {
            return serviceConfig.getUserDisplayNameAttribute(realm);
        } catch (SMSException | SSOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.WEBAUTHN_SERVICE_CONFIG_ERROR, e);
        }
    }

    private AMIdentity getIdentityByUsername(String username, String realm) throws WebAuthnCeremonyException {
        AMIdentityRepository repository = AuthD.getAuth().getAMIdentityRepository(realm);
        IdSearchControl control = searchControl();
        try {
            IdSearchResults searchResults = repository.searchIdentities(USER, username, control);
            Set<?> results = searchResults == null ? Collections.emptySet() : searchResults.getSearchResults();
            if (results.isEmpty()) {
                throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED);
            }
            if (results.size() > 1) {
                throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED);
            }
            Object result = results.iterator().next();
            if (result instanceof AMIdentity) {
                return (AMIdentity) result;
            }
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED);
        } catch (IdRepoException | SSOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED, e);
        }
    }

    private Optional<AMIdentity> findIdentity(CrestQuery query, String realm) throws WebAuthnCeremonyException {
        AMIdentityRepository repository = AuthD.getAuth().getAMIdentityRepository(realm);
        try {
            IdSearchResults searchResults = repository.searchIdentities(USER, query, searchControl());
            Set<?> results = searchResults == null ? Collections.emptySet() : searchResults.getSearchResults();
            if (results.isEmpty()) {
                return Optional.empty();
            }
            if (results.size() > 1) {
                throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED);
            }
            Object result = results.iterator().next();
            if (result instanceof AMIdentity) {
                return Optional.of((AMIdentity) result);
            }
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED);
        } catch (IdRepoException | SSOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED, e);
        }
    }

    private IdSearchControl searchControl() {
        IdSearchControl control = new IdSearchControl();
        control.setRecursive(true);
        control.setAllReturnAttributes(true);
        control.setMaxResults(NO_LIMIT);
        return control;
    }

    @SuppressWarnings("unchecked")
    private <T> T getAttributeValue(AMIdentity identity, String attributeName)
            throws WebAuthnCeremonyException {
        try {
            Set<T> attribute = identity.getAttribute(attributeName);
            if (attribute != null && !attribute.isEmpty()) {
                return attribute.iterator().next();
            }
            return null;
        } catch (IdRepoException | SSOException e) {
            throw new WebAuthnCeremonyException(WebAuthnCeremonyError.USER_LOOKUP_FAILED, e);
        }
    }
}
