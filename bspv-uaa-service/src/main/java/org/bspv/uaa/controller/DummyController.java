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
package org.bspv.uaa.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class DummyController {

    @Value("${spring.application.name}")
    private String applicationName;

    @GetMapping("/uaa/")
    public Mono<String> greetings() {
        return Mono.just(String.format("Greetings from %s !", this.applicationName));
    }

    @GetMapping("/uaa/hello/")
    public Mono<String> greetings(@AuthenticationPrincipal final Principal principal) {
        return Mono.just(String.format("Hello %s from %s !", principal.getName(), this.applicationName));
    }

}
