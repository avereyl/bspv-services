package org.bspv.pharma;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class PharmaServiceApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(PharmaServiceApplication.class, args);
    }
    
}
