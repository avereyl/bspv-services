package org.bspv.pharma;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
// @EnableDiscoveryClient
public class PharmaServiceApplication {

    public static void main(final String[] args) {
        SpringApplication.run(PharmaServiceApplication.class, args);
    }

}
