package com.studyworld.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProperties(
        String frontendUrl,
        MfaProperties mfa,
        SecurityProperties security,
        Duration verificationTokenTtl,
        Duration passwordResetTokenTtl
) {
    public record MfaProperties(
            String issuer,
            int qrWidth,
            int qrHeight
    ) {
    }

    public record SecurityProperties(
            int maxFailedAttempts,
            Duration lockoutDuration,
            Duration passwordExpiry
    ) {
    }
}
