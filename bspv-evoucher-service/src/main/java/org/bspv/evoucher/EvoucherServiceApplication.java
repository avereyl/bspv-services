package org.bspv.evoucher;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
// @EnableDiscoveryClient
public class EvoucherServiceApplication {

    public static void main(final String[] args) {
        SpringApplication.run(EvoucherServiceApplication.class, args);
    }

    @Bean
    // @LoadBalanced
    public WebClient.Builder loadBalancedWebClientBuilder() {
        return WebClient.builder();
    }
}
