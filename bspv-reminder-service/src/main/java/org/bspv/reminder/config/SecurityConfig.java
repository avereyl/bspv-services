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
package org.bspv.reminder.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bspv.lib.security.BspvSecurityConstant;
import org.bspv.lib.security.ServerWebExchangeCookieAuthenticationConverter;
import org.bspv.lib.security.SignedJWTAuthTokenConverter;
import org.bspv.lib.security.SignedJWTDecoder;
import org.bspv.lib.security.SignedJWTReactiveAuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class SecurityConfig {

    @Value("${security.key.path:classpath:publickey.txt}")
    private String publicKeyPath;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity http) {
    //  @formatter:off
        return http
            .addFilterAt(this.accessTokenAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .exceptionHandling()
                 .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(HttpStatus.UNAUTHORIZED))
                 .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
            .authorizeExchange()
                .matchers(new PathPatternParserServerWebExchangeMatcher("/", HttpMethod.GET)).permitAll()
                .anyExchange().authenticated()
            .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .csrf().disable() // handle at gateway level
            .logout().disable()
            .build()
        ;
//  @formatter:on
    }

    @Bean
    public AuthenticationWebFilter accessTokenAuthenticationWebFilter() {
        final AuthenticationWebFilter filter = new AuthenticationWebFilter(this.jwtAuthenticationManager());
        filter.setServerAuthenticationConverter(new ServerWebExchangeCookieAuthenticationConverter(
                BspvSecurityConstant.DEFAULT_ACCESS_TOKEN_COOKIE_NAME));
        filter.setAuthenticationSuccessHandler(new WebFilterChainServerAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(this.serverAuthenticationFailureHandler());
        return filter;
    }

    @Bean
    public ReactiveAuthenticationManager jwtAuthenticationManager() {
        final SignedJWTDecoder decoder = new SignedJWTDecoder(this.publicKey());
        final SignedJWTReactiveAuthenticationManager manager = new SignedJWTReactiveAuthenticationManager(decoder);
        manager.setAuthenticationTokenConverter(new SignedJWTAuthTokenConverter());
        return manager;
    }

    @Bean
    public ServerAuthenticationFailureHandler serverAuthenticationFailureHandler() {
        return new ServerAuthenticationEntryPointFailureHandler(
                new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));
    }

    @Bean
    // @LoadBalanced
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    private RSAPublicKey publicKey() {
        RSAPublicKey key = null;
        try (InputStream readStream = this.resourceLoader.getResource(this.publicKeyPath).getInputStream();) {
            final CertificateFactory f = CertificateFactory.getInstance("X.509");
            final X509Certificate certificate = (X509Certificate) f.generateCertificate(readStream);
            key = (RSAPublicKey) certificate.getPublicKey();
        } catch (IOException | CertificateException e) {
            log.error("Unable to load public key", e);
        }
        return key;
    }

}
