package com.studyworld;

import com.studyworld.config.AppProperties;
import com.studyworld.config.JwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties({AppProperties.class, JwtProperties.class})
public class Studyworld {
    private static final Logger log = LoggerFactory.getLogger(Studyworld.class);

    public static void main(String[] args) {
        SpringApplication.run(Studyworld.class, args);
    }

    @Bean
    ApplicationRunner logFrontendUrl(AppProperties appProperties) {
        return args -> log.info("Frontend URL for CORS and links: {}", appProperties.frontendUrl());
    }
}
