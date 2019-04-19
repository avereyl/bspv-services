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

import org.bspv.lib.security.exception.BspvAuthException;
import org.bspv.lib.security.exception.BspvAuthJWTError;
import org.bspv.lib.security.exception.BspvAuthJWTException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;

import lombok.Setter;
import reactor.core.publisher.Mono;

public class SignedJWTReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final SignedJWTDecoder decoder;

    public SignedJWTReactiveAuthenticationManager(final SignedJWTDecoder decoder) {
        this.decoder = decoder;
    }

    @Setter
    private SignedJWTAuthTokenConverter authenticationTokenConverter;

    @Override
    public Mono<Authentication> authenticate(final Authentication authentication) {
// @formatter:off
        return Mono.justOrEmpty(authentication)
                .filter(a -> a instanceof BearerAuthToken)
                .cast(BearerAuthToken.class)
                .map(BearerAuthToken::getToken)
                .flatMap(this.decoder::decode)
                // TODO include the ability to reload user account from userDetails service
                .flatMap(this.authenticationTokenConverter::convert)
                .cast(Authentication.class)
                .onErrorMap(BspvAuthJWTException.class, this::onError);
// @formatter:on
    }

    private BspvAuthException onError(final BspvAuthJWTException e) {
        final BspvAuthJWTError invalidRequest = BspvAuthJWTError.invalidToken(e.getMessage());
        return new BspvAuthException(invalidRequest, e.getMessage());
    }
}
