package org.bspv.uaa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * This application is our "user authentication and authorization server".
 *
 */
@SpringBootApplication
public class UAAServiceApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(UAAServiceApplication.class, args);
    }
    
}
