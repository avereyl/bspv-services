package org.bspv.gateway.config.security;

import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Stupid controller advice to explicitly subscribe to csrfToken Mono. This token is not used later on, because this is
 * a REST API therefore there is no use of the token in web pages rendering, hence we should force the subscription.
 *
 * @author guillaume
 *
 */
@ControllerAdvice
public class XSRFControllerAdvice {

    /**
     *
     * @see CookieCsrfTokenRepository
     * @see https://github.com/spring-projects/spring-security/issues/5766
     *
     * @param exchange
     *            The {@link ServerWebExchange}
     * @return a {@link Mono} of a {@link CsrfToken}
     */
    @ModelAttribute
    Mono<CsrfToken> csrfToken(final ServerWebExchange exchange) {
        final Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        csrfToken.subscribe(token -> {
            // nothing done here, subscribing will fire CookieCsrfTokenRepository#saveToken
        });
        return csrfToken;
    }
}
