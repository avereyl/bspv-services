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

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;

import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Transient
public class SignedJWTAuthToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = BspvSecurityConstant.SERIAL_VERSION_UID;

    @Getter
    private final SignedJWT token;

    /**
     * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
     *
     * @param token
     *            the JWT token
     */
    public SignedJWTAuthToken(final SignedJWT token) {
        super(Collections.emptyList());
        this.token = token;
    }

    /**
     * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
     *
     * @param token
     *            the JWT token
     * @param authorities
     *            the authorities assigned to the JWT
     */
    public SignedJWTAuthToken(final SignedJWT token, final Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.setAuthenticated(true);
    }

    /**
     * Return claims of this JWT.
     *
     * @return Claims as a {@link Map}.
     */
    public Map<String, Object> getTokenAttributes() {
        try {
            return this.getToken().getJWTClaimsSet().getClaims();
        } catch (final ParseException e) {
            log.error("Unable to access token attributes.", e);
        }
        return Collections.emptyMap();
    }

    /**
     * The {@link Jwt}'s subject, if any
     */
    @Override
    public String getName() {
        try {
            return this.getToken().getJWTClaimsSet().getSubject();
        } catch (final ParseException e) {
            log.error("Unable to access token subject claim.", e);
        }
        return "";
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.Authentication#getCredentials()
     */
    @Override
    public Object getCredentials() {
        return this.getToken();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.core.Authentication#getPrincipal()
     */
    @Override
    public Object getPrincipal() {
        return this.getToken();
    }

}