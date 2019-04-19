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

import java.util.Optional;

import org.bspv.lib.security.BspvSecurityConstant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

/**
 * This writer is responsible for writing/deleting authentication tokens as cookies. HTTP only cookies are not
 * accessible by XSS exploit.
 *
 * @author guillaume
 *
 */
public class BspvAuthenticationTokenCookieWriter {

    @Value("${security.cookie-path}")
    private String cookiePath;

    @Value("${security.endpoint.refresh:/uaa/refresh}")
    private String refreshEndpointPath;

    /**
     * Saves the access token using the {@link ServerWebExchange}. If the token is null, it is the same as deleting it.
     *
     * @param accessToken
     *            the access token to save or null to delete
     * @param webExchange
     *            the {@link ServerWebExchange} to use
     */
    public void saveAccessToken(final ServerWebExchange webExchange, final String accessToken) {
        final String tokenToSave = accessToken != null ? accessToken : "";
        final String path = this.getRequestContext(webExchange.getRequest());
        final long maxAge = StringUtils.isEmpty(tokenToSave) ? 0 : -1;
//      @formatter:off
        final ResponseCookie cookie = ResponseCookie.from(BspvSecurityConstant.DEFAULT_ACCESS_TOKEN_COOKIE_NAME, tokenToSave)
                .domain(webExchange.getRequest().getURI().getHost())
                .httpOnly(true)
                .maxAge(maxAge)
                .path(path)
                .secure(Optional.ofNullable(webExchange.getRequest().getSslInfo()).map(sslInfo -> true).orElse(false))
                .sameSite("Lax").build();
//      @formatter:on
        webExchange.getResponse().addCookie(cookie);
    }

    /**
     * Saves the refresh token using the {@link ServerWebExchange}. If the token is null, it is the same as deleting it.
     *
     * @param refreshToken
     *            the refresh token to save or null to delete
     * @param webExchange
     *            the {@link ServerWebExchange} to use
     */
    public void saveRefreshToken(final ServerWebExchange webExchange, final String refreshToken) {
        final String tokenToSave = refreshToken != null ? refreshToken : "";
        String path = this.getRequestContext(webExchange.getRequest());
        path = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        path = path.concat(this.refreshEndpointPath);
        final long maxAge = StringUtils.isEmpty(tokenToSave) ? 0 : -1;
//      @formatter:off
        final ResponseCookie cookie = ResponseCookie
                .from(BspvSecurityConstant.DEFAULT_REFRESH_TOKEN_COOKIE_NAME, tokenToSave)
                .domain(webExchange.getRequest().getURI().getHost())
                .httpOnly(true)
                .maxAge(maxAge)
                .path(path)
                .secure(Optional.ofNullable(webExchange.getRequest().getSslInfo()).map(sslInfo -> true).orElse(false))
                .sameSite("Lax").build();
//      @formatter:on
        webExchange.getResponse().addCookie(cookie);
    }

    private String getRequestContext(final ServerHttpRequest request) {
        final String contextPath = request.getPath().contextPath().value();
        return StringUtils.hasLength(contextPath) ? contextPath : "/";
    }

}
