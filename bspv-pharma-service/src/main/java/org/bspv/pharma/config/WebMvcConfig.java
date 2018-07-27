package org.bspv.pharma.config;

import java.util.List;

import org.bspv.commons.security.model.BspvPrincipal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.MethodParameter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 
 *
 */
@Configuration
@EnableWebSecurity
public class WebMvcConfig implements WebMvcConfigurer {

    
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(currentUserHandlerMethodArgumentResolver());
    }

    /**
     * Define a new argument resolver to get the current user.
     * @return
     */
    @Bean
    public HandlerMethodArgumentResolver currentUserHandlerMethodArgumentResolver() {
        return new HandlerMethodArgumentResolver() {
            @Override
            public boolean supportsParameter(MethodParameter parameter) {
                return parameter.getParameterType().equals(BspvPrincipal.class);
            }

            @Override
            public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                    NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
                try {
                    return (BspvPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                } catch (Exception e) {
                    return null;
                }
            }
        };
    }
}
