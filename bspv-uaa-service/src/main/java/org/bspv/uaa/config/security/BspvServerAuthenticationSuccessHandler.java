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

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.web.server.ServerWebExchange;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * This class handles the persistence of successful authentication result in the HTTP response. JWT tokens are build
 * from the authentication. The persistence work is delegated to a {@link BspvAuthenticationTokenCookieWriter
 * cookieWriter}.
 *
 * @author BILLAUDG
 *
 */
@Slf4j
public class BspvServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    /**
     * Authorities of this access token
     */
    public static final String SCOPE_CLAIM = "scp";

    @Value("${spring.application.name}")
    private String applicationName;

    private final JWSSigner signer;

    @Autowired
    private BspvAuthenticationTokenCookieWriter cookieWriter;

    public BspvServerAuthenticationSuccessHandler(final RSAPrivateKey privateKey) {
        this.signer = new RSASSASigner(privateKey);
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(final WebFilterExchange exchange, final Authentication authentication) {
        final ServerWebExchange webExchange = exchange.getExchange();
        webExchange.getResponse().setStatusCode(HttpStatus.OK);

        if (!AbstractAuthenticationToken.class.isInstance(authentication)) {
            log.error("The authentication is not an instance of the expected class. Expected {}, actual {}",
                    AbstractAuthenticationToken.class, authentication.getClass());
            return Mono.error(new InternalAuthenticationServiceException(
                    "Cannot serialize an Authentication which is not an AbstractAuthenticationToken instance."));
        }

        final AbstractAuthenticationToken auth = AbstractAuthenticationToken.class.cast(authentication);

        final List<String> authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        final UUID accessTokenId = UUID.randomUUID();
        final UUID refreshTokenId = UUID.randomUUID();
        final LocalDateTime issuedAt = LocalDateTime.now(ZoneOffset.UTC);
        final LocalDateTime accessTokenEexpirationTime = issuedAt.plus(Duration.ofHours(1L));
        final LocalDateTime refreshTokenEexpirationTime = issuedAt.plus(Duration.ofDays(30L));

        // Prepare access JWT with claims set
        final JWTClaimsSet accessTokenClaimsSet = new JWTClaimsSet.Builder()
//              @formatter:off
                .jwtID(accessTokenId.toString())
                .issuer(this.applicationName)
                .issueTime(Date.from(issuedAt.toInstant(ZoneOffset.UTC)))
                .expirationTime(Date.from(accessTokenEexpirationTime.toInstant(ZoneOffset.UTC)))
                .subject(auth.getName())
                .claim(SCOPE_CLAIM, authorities)
//              @formatter:on
                .build();

        // Prepare refresh JWT with claims set
        final JWTClaimsSet refreshTokenClaimsSet = new JWTClaimsSet.Builder()
//              @formatter:off
                .jwtID(refreshTokenId.toString())
                .claim("ati", accessTokenId.toString())
                .issuer(this.applicationName)
                .issueTime(Date.from(issuedAt.toInstant(ZoneOffset.UTC)))
                .expirationTime(Date.from(refreshTokenEexpirationTime.toInstant(ZoneOffset.UTC)))
                .subject(auth.getName())
                .claim(SCOPE_CLAIM, authorities)
//              @formatter:on
                .build();

        final SignedJWT signedAccessToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), accessTokenClaimsSet);
        final SignedJWT signedRefreshToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), refreshTokenClaimsSet);

        // Apply the HMAC protection
        try {
            signedAccessToken.sign(this.signer);
            signedRefreshToken.sign(this.signer);
        } catch (final JOSEException e) {
            log.error("Unable to sign JWT tokens", e);
            return Mono.error(new InternalAuthenticationServiceException("Cannot sign JWT tokens."));
        }

        // Serialize to compact form
        final String accessToken = signedAccessToken.serialize();
        final String refreshToken = signedRefreshToken.serialize();

        // add cookies to response
        this.cookieWriter.saveAccessToken(webExchange, accessToken);
        this.cookieWriter.saveRefreshToken(webExchange, refreshToken);

        final DataBuffer buffer = webExchange.getResponse().bufferFactory().wrap("".getBytes(StandardCharsets.UTF_8));
        return webExchange.getResponse().writeWith(Mono.just(buffer));
    }

}
