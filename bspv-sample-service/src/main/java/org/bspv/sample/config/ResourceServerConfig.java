package org.bspv.sample.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
/*@EnableResourceServer enables a Spring Security filter that authenticates requests using an incoming OAuth2 token.*/
@EnableGlobalMethodSecurity(prePostEnabled = true)

public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
/*class ResourceServerConfigurerAdapter implements ResourceServerConfigurer providing methods to adjust the access rules and paths that are protected by OAuth2 security.*/

    @Autowired
    public TokenStore tokenStore;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .anonymous().disable()
            .authorizeRequests().anyRequest().fullyAuthenticated()
        .and()
            .cors().disable()
            .csrf().disable()
            .httpBasic().disable()
            .exceptionHandling()
            .authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
            .accessDeniedHandler((request, response, authException) -> response.sendError(HttpServletResponse.SC_FORBIDDEN))
        .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//         .and()
//            .addFilterAfter(oauth2ClientContextFilter, ExceptionTranslationFilter.class)
            ;

    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("bspv/sample-service").tokenStore(tokenStore);
    }
    
    
    
    
    
    
}