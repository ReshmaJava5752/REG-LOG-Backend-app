package com.example.registrationlogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class RegistrationLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(RegistrationLoginApplication.class, args);
    }
}
