package com.studyworld.token.model;

import java.time.Instant;
import java.util.UUID;

public record JwtToken(
        UUID id,
        UUID userId,
        String token,
        TokenType type,
        Instant issuedAt,
        Instant expiresAt,
        boolean revoked,
        Instant createdAt
) {
}
