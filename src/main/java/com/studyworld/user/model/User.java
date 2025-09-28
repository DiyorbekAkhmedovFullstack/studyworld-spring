package com.studyworld.user.model;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record User(
        UUID id,
        String email,
        String passwordHash,
        String firstName,
        String lastName,
        String phone,
        boolean enabled,
        boolean emailVerified,
        boolean mfaEnabled,
        String mfaSecret,
        int failedAttempts,
        Instant lockoutUntil,
        Instant passwordUpdatedAt,
        Instant passwordExpiresAt,
        String profilePictureUrl,
        Instant createdAt,
        Instant updatedAt,
        Set<UserRole> roles
) {
    public boolean isLocked(Instant now) {
        return lockoutUntil != null && lockoutUntil.isAfter(now);
    }

    public boolean isPasswordExpired(Instant now) {
        return passwordExpiresAt != null && passwordExpiresAt.isBefore(now);
    }
}
