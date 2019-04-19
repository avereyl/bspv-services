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
package org.bspv.evoucher.controller;

import java.util.Optional;

import org.bspv.lib.security.BspvSecurityConstant;
import org.bspv.lib.security.SignedJWTAuthToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@RestController
public class DummyController {

    @Value("${spring.application.name}")
    private String applicationName;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @GetMapping("/")
    public Mono<String> greetings() {
        return Mono.just(String.format("Greetings from %s !", this.applicationName));
    }

    @GetMapping("/toUAA/")
    public Mono<String> greetingsFromUAA(final Authentication authentication) {
//      @formatter:off
        return this.webClientBuilder.build()
//                .get().uri("http://uaa-service/uaa/")
                .get().uri("http://localhost:8081/uaa/hello/")
                .cookie(BspvSecurityConstant.DEFAULT_ACCESS_TOKEN_COOKIE_NAME, this.getTokenValue(authentication))
                .retrieve()
                .bodyToMono(String.class);
//      @formatter:on
    }

    private String getTokenValue(final Authentication authentication) {
//      @formatter:off
       return Optional.ofNullable(authentication)
               .filter(SignedJWTAuthToken.class::isInstance)
               .map(auth -> ((SignedJWTAuthToken) auth).getToken().getParsedString())
               .orElse("");
//      @formatter:on
    }

}
