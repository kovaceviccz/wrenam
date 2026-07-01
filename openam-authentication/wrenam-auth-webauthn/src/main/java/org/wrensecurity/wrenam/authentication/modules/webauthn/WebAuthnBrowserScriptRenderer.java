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
package org.wrensecurity.wrenam.authentication.modules.webauthn;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.forgerock.openam.utils.IOUtils;
import org.forgerock.util.Reject;

/**
 * Render WebAuthn browser script callbacks from resource templates and public-key options JSON.
 */
public class WebAuthnBrowserScriptRenderer {

    private static final String PUBLIC_KEY_PLACEHOLDER = "{publicKeyB64}";

    /**
     * Create a browser script renderer.
     */
    @Inject
    public WebAuthnBrowserScriptRenderer() {
    }

    /**
     * Render a script callback using the provided class loader and script resource.
     *
     * @param classLoader class loader used to resolve the script template
     * @param templateResourceName browser script template resource
     * @param publicKeyJson public key options JSON
     * @return rendered script callback
     * @throws IOException if the script template cannot be read
     */
    public ScriptTextOutputCallback render(ClassLoader classLoader, String templateResourceName,
            String publicKeyJson) throws IOException {
        Reject.ifNull(classLoader, templateResourceName, publicKeyJson);
        InputStream templateStream = classLoader.getResourceAsStream(templateResourceName);
        if (templateStream == null) {
            throw new IOException("Missing WebAuthn browser script template: " + templateResourceName);
        }
        String template = IOUtils.readStream(templateStream);
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(publicKeyJson.getBytes(StandardCharsets.UTF_8));
        return new ScriptTextOutputCallback(template.replace(PUBLIC_KEY_PLACEHOLDER, encoded));
    }

}
