/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bspv.lib.security;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

public class BearerAuthToken extends AbstractAuthenticationToken {

    /**
     *
     */
    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    private String token;

    /**
     * Create a {@code BearerAuthenticationToken} using the provided parameter(s)
     *
     * @param token
     *            - the bearer token
     */
    public BearerAuthToken(final String token) {
        super(Collections.emptyList());
        Assert.hasText(token, "token cannot be empty");
        this.token = token;
    }

    /**
     * Get the <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>
     *
     * @return the token that proves the caller's authority to perform the request/exchange
     */
    public String getToken() {
        return this.token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getCredentials() {
        return this.getToken();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getPrincipal() {
        return this.getToken();
    }

}
