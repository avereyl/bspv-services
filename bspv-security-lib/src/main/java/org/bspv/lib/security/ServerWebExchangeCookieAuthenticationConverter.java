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
/**
 *
 */
package org.bspv.lib.security;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bspv.lib.security.exception.BspvAuthError;
import org.bspv.lib.security.exception.BspvAuthException;
import org.bspv.lib.security.exception.BspvAuthJWTError;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import lombok.Getter;
import reactor.core.publisher.Mono;

/**
 *
 * @author guillaume
 *
 */
public class ServerWebExchangeCookieAuthenticationConverter implements ServerAuthenticationConverter {

    static final String DEFAULT_AUTHENTICATION_COOKIE_NAME = "AUTHENTICATION-TOKEN";
    private static final Pattern tokenPattern = Pattern.compile("^(?<token>[a-zA-Z0-9-._~+/]+)=*$");

    @Getter
    private final String cookieName;

    public ServerWebExchangeCookieAuthenticationConverter() {
        super();
        this.cookieName = DEFAULT_AUTHENTICATION_COOKIE_NAME;
    }

    public ServerWebExchangeCookieAuthenticationConverter(final String cookieName) {
        super();
        this.cookieName = cookieName;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.security.web.server.authentication.ServerAuthenticationConverter#convert(org.springframework.
     * web.server.ServerWebExchange)
     */
    @Override
    public Mono<Authentication> convert(final ServerWebExchange exchange) {
        return Mono.justOrEmpty(this.token(exchange.getRequest())).map(BearerAuthToken::new);
    }

    private String token(final ServerHttpRequest request) {
        final String authorizationHeaderToken = this.resolveFromCookies(request.getCookies());
        if (authorizationHeaderToken != null) {
            return authorizationHeaderToken;
        }
        return null;
    }

    private String resolveFromCookies(final MultiValueMap<String, HttpCookie> cookies) {
// @formatter:off
        final Optional<HttpCookie> authCookie = cookies.entrySet()
                .stream()
                .filter(e -> this.cookieName.equals(e.getKey()))
                .flatMap(e -> e.getValue().stream())
                .findFirst();
// @formatter:on
        if (authCookie.isPresent()) {
            final String authorization = authCookie.get().getValue();
            if (StringUtils.hasText(authorization)) {
                final Matcher matcher = tokenPattern.matcher(authorization);
                if (!matcher.matches()) {
                    final BspvAuthError error = BspvAuthJWTError.invalidToken();
                    throw new BspvAuthException(error);
                }
                return matcher.group("token");
            }
        }
        return null;
    }

}
