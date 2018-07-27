package org.bspv.uaa.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 
 *
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        // defining users with password and roles
        // @formatter:off
        auth
            .inMemoryAuthentication()
            .withUser("admin").password("{noop}admin").roles("USER","ADMIN")
            .and()
            .withUser("user").password("{noop}password").roles("USER")
            ;
        // @formatter:on   
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter#authenticationManagerBean()
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        // exposing the authentication manager as a spring bean for autowiring.
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
//      @formatter:off
        http
            .authorizeRequests()
                .antMatchers("/login").permitAll() //
                .antMatchers("/token").permitAll()
                .anyRequest().authenticated()
            .and().formLogin().permitAll()
            .and()
            .httpBasic().disable()
            .csrf().disable()
//            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        ;
//      @formatter:on
    }
    
    
}
