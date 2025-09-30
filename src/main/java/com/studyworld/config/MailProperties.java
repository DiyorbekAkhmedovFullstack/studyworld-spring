package com.studyworld.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.mail")
public record MailProperties(
        String fromEmail,
        String fromName,
        ResendProperties resend
) {
    public record ResendProperties(
            String apiKey
    ) {}
}
