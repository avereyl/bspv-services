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

import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.bspv.lib.security.exception.BspvAuthException;
import org.bspv.lib.security.exception.BspvAuthJWTError;
import org.bspv.lib.security.exception.BspvAuthJWTException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

import reactor.core.publisher.Mono;

/**
 * A decoder implementation that &quot;decodes&quot; a JSON Web Token (JWT) and additionally verifies it's digital
 * signature if the JWT is a JSON Web Signature (JWS). The public key used for verification is obtained from the
 * {@link RSAPublicKey} supplied via the constructor.
 *
 */
public class SignedJWTDecoder {

    private final JWTProcessor<JWKSecurityContext> tokenProcessor;

    // should be access in a non blocking way
    private final JWKSource<JWKSecurityContext> keySource;

    public SignedJWTDecoder(final RSAPublicKey publicKey) {
        final JWSAlgorithm algo = JWSAlgorithm.parse(JWSAlgorithm.RS256.getName());
        final RSAKey rsaKey = rsaKey(publicKey);
        final JWKSet jwkSet = new JWKSet(rsaKey);

        final JWKSource<JWKSecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);
        final JWSKeySelector<JWKSecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(algo, jwkSource);
        final DefaultJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>());// TODO might be injected

        this.tokenProcessor = jwtProcessor;
        this.keySource = jwkSource;

    }

    /**
     * Decode the given token into a {@link Mono} {@link SignedJWT}
     * 
     * @param token
     *            The token to decode as {@link String}
     * @return {@link Mono} of a {@link SignedJWT}.
     */
    public Mono<SignedJWT> decode(final String token) {
        final JWT jwt = this.parse(token);
        if (jwt instanceof SignedJWT) {
            return this.decode((SignedJWT) jwt);
        }
        throw new BspvAuthJWTException(BspvAuthJWTError.unsupportedToken(), "Only signed JWT are supported");
    }

    /**
     * Parse the given token (as a {@link String}) into a {@link JWT} token.
     *
     * @param token
     *            The token to be parsed
     * @return a new {@link JWT} token
     */
    private JWT parse(final String token) {
        try {
            return JWTParser.parse(token);
        } catch (final Exception ex) {
            throw new BspvAuthJWTException(BspvAuthJWTError.invalidToken(),
                    "An error occurred while attempting to decode the token: " + ex.getMessage(), ex);
        }
    }

    /**
     * To decode the given {@link SignedJWT}, a new instance is created from the given one which is then validated.
     *
     * @param signedJwt
     * @return
     */
    private Mono<SignedJWT> decode(final SignedJWT signedJwt) {
        try {
            final JWKSelector keySelector = new JWKSelector(JWKMatcher.forJWSHeader(signedJwt.getHeader()));
// @formatter:off
            return  Mono.fromCallable(() -> this.keySource.get(keySelector, null))
                    .onErrorMap(e -> new IllegalStateException("Could not obtain the keys", e)) // check that a key is available for this token
                    .map(jwkList -> this.createClaimsSet(signedJwt, jwkList)) //create claims set from the given token and key (signature is checked here)
                    .map(jwt -> signedJwt)// return initial token instance (if signature validity failed an exception is thrown from previous state)
                    .onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof BspvAuthJWTException),
                            e -> new BspvAuthJWTException("An error occurred while attempting to decode the Jwt: ", e));
// @formatter:on
        } catch (final RuntimeException ex) {
            throw new BspvAuthException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
        }
    }

    private JWTClaimsSet createClaimsSet(final JWT parsedToken, final List<JWK> jwkList) {
        try {
            return this.tokenProcessor.process(parsedToken, new JWKSecurityContext(jwkList));
        } catch (BadJOSEException | JOSEException e) {
            // log.
            throw new BspvAuthJWTException("Failed to validate the token", e);
        }
    }

    private static RSAKey rsaKey(final RSAPublicKey publicKey) {
        return new RSAKey.Builder(publicKey).build();
    }

}
