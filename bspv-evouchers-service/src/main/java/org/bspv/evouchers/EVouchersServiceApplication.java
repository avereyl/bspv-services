package org.bspv.evouchers;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class EVouchersServiceApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(EVouchersServiceApplication.class, args);
    }
    
}
