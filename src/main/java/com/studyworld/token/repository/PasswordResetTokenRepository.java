package com.studyworld.token.repository;

import com.studyworld.token.model.PasswordResetToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepository {

    PasswordResetToken create(UUID userId, Instant expiresAt);

    Optional<PasswordResetToken> find(UUID tokenId);

    void markConsumed(UUID tokenId);
}
