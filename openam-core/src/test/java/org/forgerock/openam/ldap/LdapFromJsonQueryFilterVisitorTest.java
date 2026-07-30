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
package org.forgerock.openam.ldap;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.resource.QueryFilters;
import org.forgerock.opendj.ldap.Filter;
import org.forgerock.util.query.QueryFilter;
import org.testng.annotations.Test;

public class LdapFromJsonQueryFilterVisitorTest {

    @Test
    public void shouldMapResourceIdentifiersToTheRepositorySearchAttribute() {
        QueryFilter<JsonPointer> queryFilter =
                QueryFilters.parse("_id co \"alice\" or (cn eq \"Admin\" and mail co \"example.org\")");

        Filter filter = queryFilter.accept(new LdapFromJsonQueryFilterVisitor("uid"), null);

        assertThat(filter.toString()).isEqualTo("(|(uid=*alice*)(&(cn=Admin)(mail=*example.org*)))");
    }

    @Test
    public void shouldUseJsonFieldNamesWhenNoSearchAttributeIsConfigured() {
        QueryFilter<JsonPointer> queryFilter = QueryFilters.parse("_id eq \"alice\" or mail co \"example.org\"");

        Filter filter = queryFilter.accept(new LdapFromJsonQueryFilterVisitor(), null);

        assertThat(filter.toString()).isEqualTo("(|(_id=alice)(mail=*example.org*))");
    }

    @Test
    public void shouldEscapeRepositoryAssertionValues() {
        QueryFilter<JsonPointer> queryFilter = QueryFilters.parse("_id eq \"a*b(c)\\\\\"");

        Filter filter = queryFilter.accept(new LdapFromJsonQueryFilterVisitor("uid"), null);

        assertThat(filter.toString()).isEqualTo("(uid=a\\2Ab\\28c\\29\\5C)");
    }

}
