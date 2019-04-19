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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class SignedJWTAuthTokenConverter implements Converter<SignedJWT, Mono<AbstractAuthenticationToken>> {

    private static final String SCOPE_CLAIM_NAME = "scp";

    @Override
    public final Mono<AbstractAuthenticationToken> convert(final SignedJWT jwt) {
        final Collection<GrantedAuthority> authorities = this.extractAuthorities(jwt);
        return Mono.just(new SignedJWTAuthToken(jwt, authorities));
    }

    protected Collection<GrantedAuthority> extractAuthorities(final SignedJWT jwt) {
        return this.getScopes(jwt).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private Collection<String> getScopes(final SignedJWT jwt) {
        try {
            final Object scopes = jwt.getJWTClaimsSet().getClaim(SCOPE_CLAIM_NAME);
            if (scopes instanceof String) {
                if (StringUtils.hasText((String) scopes)) {
                    return Arrays.asList(((String) scopes).split(" "));
                } else {
                    return Collections.emptyList();
                }
            } else if (scopes instanceof Collection) {
                return (Collection<String>) scopes;
            }
        } catch (final ParseException e) {
            log.error("Cannot access to scope claim in the provided token.");
        }
        return Collections.emptyList();
    }

}
