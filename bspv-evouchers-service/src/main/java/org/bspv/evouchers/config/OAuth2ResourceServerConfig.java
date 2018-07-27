package org.bspv.evouchers.config;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.io.IOUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * ResourceServerConfigurerAdapter#configure(org.springframework.security.config
     * .annotation.web.builders.HttpSecurity)
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
        .anyRequest().authenticated();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.oauth2.config.annotation.web.configuration.
     * ResourceServerConfigurerAdapter#configure(org.springframework.security.oauth2
     * .config.annotation.web.configurers.ResourceServerSecurityConfigurer)
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenServices(tokenServices());
    }

    @Bean
    public TokenStore tokenStore() {
        /**
         * A {@link TokenStore} implementation that just reads data from the tokens
         * themselves.
         * 
         * @see JwtTokenStore
         */
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        // loading the public key of the UAA service
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        final Resource resource = new ClassPathResource("public.key");
        String publicKey = null;
        try {
            publicKey = IOUtils.toString(resource.getInputStream(), Charset.defaultCharset());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        // set verifier key and claims verifier
        converter.setVerifierKey(publicKey);
        converter.setJwtClaimsSetVerifier(jwtClaimsSetVerifier());
        return converter;
    }
    
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }



    @Bean
    public JwtClaimsSetVerifier jwtClaimsSetVerifier() {
        // TODO No-op verifier !
        return claims -> {

        };
    }

}
