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
package org.bspv.uaa.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;

import reactor.core.publisher.Mono;

/**
 * This logout handler is responsible for deleting access and refresh cookies.
 *
 * @author BILLAUDG
 *
 */
public class BspvServerLogoutHandler implements ServerLogoutHandler {

    @Autowired
    private BspvAuthenticationTokenCookieWriter cookieWriter;

    @Override
    public Mono<Void> logout(final WebFilterExchange exchange, final Authentication authentication) {
        this.cookieWriter.saveAccessToken(exchange.getExchange(), null);
        this.cookieWriter.saveRefreshToken(exchange.getExchange(), null);
        return Mono.empty();
    }

}
