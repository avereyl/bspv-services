package org.bspv.reminder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
// @EnableDiscoveryClient
public class ReminderServiceApplication {

    public static void main(final String[] args) {
        SpringApplication.run(ReminderServiceApplication.class, args);
    }

}
