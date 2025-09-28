package com.studyworld.token.repository;

import com.studyworld.token.model.JwtToken;
import com.studyworld.token.model.TokenType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface JwtTokenRepository {

    void save(JwtToken token);

    void revokeByToken(String token);

    void revokeAllActiveTokens(UUID userId, TokenType type);

    Optional<JwtToken> findActiveToken(String token, TokenType type, Instant now);
}
