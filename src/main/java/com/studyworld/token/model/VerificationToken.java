package com.studyworld.token.model;

import java.time.Instant;
import java.util.UUID;

public record VerificationToken(
        UUID token,
        UUID userId,
        Instant expiresAt,
        boolean consumed,
        Instant createdAt
) {
    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }

    public boolean isActive(Instant now) {
        return !consumed && !isExpired(now);
    }
}
