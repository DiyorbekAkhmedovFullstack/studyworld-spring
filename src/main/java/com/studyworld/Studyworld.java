package com.studyworld;

import com.studyworld.config.AppProperties;
import com.studyworld.config.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({AppProperties.class, JwtProperties.class})
public class Studyworld {

    public static void main(String[] args) {
        SpringApplication.run(Studyworld.class, args);
    }

}
