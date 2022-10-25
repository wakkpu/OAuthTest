package com.example.googleoauth;

import com.example.googleoauth.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class GoogleOAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(GoogleOAuthApplication.class, args);
    }

}
