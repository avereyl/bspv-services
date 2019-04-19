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
package org.bspv.uaa.config;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bspv.lib.security.BspvSecurityConstant;
import org.bspv.lib.security.ServerWebExchangeCookieAuthenticationConverter;
import org.bspv.lib.security.SignedJWTAuthTokenConverter;
import org.bspv.lib.security.SignedJWTDecoder;
import org.bspv.lib.security.SignedJWTReactiveAuthenticationManager;
import org.bspv.uaa.config.security.BspvAuthenticationTokenCookieWriter;
import org.bspv.uaa.config.security.BspvServerAuthenticationSuccessHandler;
import org.bspv.uaa.config.security.BspvServerLogoutHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.HttpStatusReturningServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

/**
 * Defines security configuration of this web application. Handles user declarations and authorization level for
 * requests
 *
 * @author BILLAUDG
 *
 */
@Configuration
public class SecurityConfig {

    @Value("${security.keystore.path:classpath:keystore.jks}")
    private String keystorePath;

    @Value("${security.keystore.password}")
    private String keystorePassword;

    @Value("${security.keystore.keypair}")
    private String keystoreKeyPair;

    @Value("${security.endpoint.login:/uaa/login}")
    private String loginEndpointPath;

    @Value("${security.endpoint.logout:/uaa/logout}")
    private String logoutEndpointPath;

    @Value("${security.endpoint.refresh:/uaa/refresh}")
    private String refreshEndpointPath;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        final UserDetails user = User.withUsername("user").password("{noop}password")
                .roles("UAA_USER", "PHA_USER", "EVO_ADMIN", "REM_ADMIN").build();
        return new MapReactiveUserDetailsService(user);
    }

    @Bean
    SecurityWebFilterChain securityFilterChain(final ServerHttpSecurity http,
            final ReactiveUserDetailsService userDetailsService) {

//  @formatter:off
        http
            .addFilterAt(this.usernamePasswordAuthenticationWebFilter(userDetailsService), SecurityWebFiltersOrder.FORM_LOGIN)
            .addFilterAt(this.refreshTokenAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .addFilterAt(this.accessTokenAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
            .exceptionHandling()
                 .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(HttpStatus.UNAUTHORIZED))
                 .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
            .authorizeExchange()
                .matchers(new PathPatternParserServerWebExchangeMatcher("/uaa/", HttpMethod.GET)).permitAll()
                .matchers(new PathPatternParserServerWebExchangeMatcher(this.loginEndpointPath, HttpMethod.POST)).permitAll()
                .matchers(new PathPatternParserServerWebExchangeMatcher(this.refreshEndpointPath, HttpMethod.POST)).permitAll()
                .anyExchange().authenticated()
            .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .csrf().disable() // handle at gateway level
            .logout()
                .logoutUrl(this.logoutEndpointPath)
                .logoutHandler(this.serverLogoutHandler())
                .logoutSuccessHandler(new HttpStatusReturningServerLogoutSuccessHandler())
        ;
//  @formatter:on
        return http.build();
    }

    /**
     * Filter responsible for the login mechanism
     *
     * @param userDetailsService
     *            A {@link ReactiveUserDetailsService} where finding the users.
     * @return A new {@link AuthenticationWebFilter} to handle username/password login.
     */
    @Bean
    public AuthenticationWebFilter usernamePasswordAuthenticationWebFilter(
            final ReactiveUserDetailsService userDetailsService) {
        final ReactiveAuthenticationManager manager = new UserDetailsRepositoryReactiveAuthenticationManager(
                userDetailsService);
        // FIXME add a user account status checker for this manager
        final AuthenticationWebFilter filter = new AuthenticationWebFilter(manager);
        filter.setRequiresAuthenticationMatcher(
                new PathPatternParserServerWebExchangeMatcher(this.loginEndpointPath, HttpMethod.POST));
        filter.setServerAuthenticationConverter(new ServerFormLoginAuthenticationConverter());
        filter.setAuthenticationSuccessHandler(this.serverAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(this.serverAuthenticationFailureHandler());
        return filter;
    }

    @Bean
    public AuthenticationWebFilter refreshTokenAuthenticationWebFilter() {
        final AuthenticationWebFilter filter = new AuthenticationWebFilter(this.jwtAuthenticationManager());
        // FIXME add a user account status checker for this manager + userDetailsService
        filter.setRequiresAuthenticationMatcher(
                new PathPatternParserServerWebExchangeMatcher(this.refreshEndpointPath, HttpMethod.POST));
        filter.setServerAuthenticationConverter(new ServerWebExchangeCookieAuthenticationConverter(
                BspvSecurityConstant.DEFAULT_REFRESH_TOKEN_COOKIE_NAME));
        filter.setAuthenticationSuccessHandler(this.serverAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(this.serverAuthenticationFailureHandler());
        return filter;
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
        final SignedJWTDecoder decoder = new SignedJWTDecoder((RSAPublicKey) this.keyPair().getPublic());
        final SignedJWTReactiveAuthenticationManager manager = new SignedJWTReactiveAuthenticationManager(decoder);
        manager.setAuthenticationTokenConverter(new SignedJWTAuthTokenConverter());
        return manager;
    }

    @Bean
    public ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler() {
        return new BspvServerAuthenticationSuccessHandler((RSAPrivateKey) this.keyPair().getPrivate());
    }

    @Bean
    public ServerAuthenticationFailureHandler serverAuthenticationFailureHandler() {
        return new ServerAuthenticationEntryPointFailureHandler(
                new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));
    }

    @Bean
    public BspvAuthenticationTokenCookieWriter cookieWriter() {
        return new BspvAuthenticationTokenCookieWriter();
    }

    @Bean
    public ServerLogoutHandler serverLogoutHandler() {
        return new BspvServerLogoutHandler();
    }

    private KeyPair keyPair() {
        try {
            final File keystoreFile = this.resourceLoader.getResource(this.keystorePath).getFile();
            final char[] password = this.keystorePassword.toCharArray();
            final PasswordProtection protection = new PasswordProtection(password);
            final KeyStore store = KeyStore.Builder.newInstance("jks", null, keystoreFile, protection).getKeyStore();

            final RSAPrivateCrtKey key = (RSAPrivateCrtKey) store.getKey(this.keystoreKeyPair, password);
            final RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            final PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            return new KeyPair(publicKey, key);
        } catch (IOException | KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException
                | InvalidKeySpecException e) {
            throw new IllegalStateException("Cannot load keys from store: " + this.keystorePath, e);
        }
    }

}
