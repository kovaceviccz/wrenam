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

define([
    "config/routes/admin/RealmsRoutes"
], (routes) => {
    describe("config/routes/admin/RealmsRoutes", () => {
        it("routes user creation through the Identities Users view", () => {
            const route = routes.realmsIdentitiesUsersNew;

            expect(route.page).to.equal(
                "org/forgerock/openam/ui/admin/views/realms/identities/users/new/NewUserContainer");
            expect(route.pattern).to.equal("realms/?/identities/users/new");
            expect(route.url.test("realms/%2F/identities/users/new")).to.equal(true);
        });

        it("routes encoded user IDs through the Identities Users editor", () => {
            const route = routes.realmsIdentitiesUsersEdit;

            expect(route.page).to.equal(
                "org/forgerock/openam/ui/admin/views/realms/identities/users/edit/EditUser");
            expect(route.pattern).to.equal("realms/?/identities/users/edit/?");
            expect(route.url.test("realms/%2F/identities/users/edit/user%20name")).to.equal(true);
        });

        it("routes encoded user and service IDs through the new User Service view", () => {
            const route = routes.realmsIdentitiesUsersServicesNew;

            expect(route.page).to.equal(
                "org/forgerock/openam/ui/admin/views/realms/identities/users/edit/services/new/" +
                "NewUserServiceContainer");
            expect(route.pattern).to.equal("realms/?/identities/users/edit/?/services/new/?");
            expect(route.url.test(
                "realms/%2F/identities/users/edit/user%20name/services/new/service%20type")).to.equal(true);
        });

        it("routes encoded user and service IDs through the User Service editor", () => {
            const route = routes.realmsIdentitiesUsersServicesEdit;

            expect(route.page).to.equal(
                "org/forgerock/openam/ui/admin/views/realms/identities/users/edit/services/edit/EditUserService");
            expect(route.pattern).to.equal("realms/?/identities/users/edit/?/services/edit/?");
            expect(route.url.test(
                "realms/%2F/identities/users/edit/user%20name/services/edit/service%20type")).to.equal(true);
        });
    });
});
