package com.studyworld.token.repository;

import com.studyworld.token.model.VerificationToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository {

    VerificationToken create(UUID userId, Instant expiresAt);

    Optional<VerificationToken> find(UUID tokenId);

    void markConsumed(UUID tokenId);
}
