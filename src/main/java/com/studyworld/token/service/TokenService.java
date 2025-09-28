package com.studyworld.token.service;

import com.studyworld.auth.service.UserPrincipal;
import com.studyworld.common.exception.UnauthorizedException;
import com.studyworld.token.model.JwtToken;
import com.studyworld.token.model.TokenType;
import com.studyworld.token.repository.JwtTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.security.core.GrantedAuthority;

@Service
public class TokenService {

    private final JwtService jwtService;
    private final JwtTokenRepository tokenRepository;
    private final Duration accessTtl;
    private final Duration refreshTtl;
    private final Duration mfaTtl;

    public TokenService(JwtService jwtService, JwtTokenRepository tokenRepository) {
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.accessTtl = jwtService.getProperties().accessTokenTtl();
        this.refreshTtl = jwtService.getProperties().refreshTokenTtl();
        this.mfaTtl = jwtService.getProperties().mfaTokenTtl();
    }

    public TokenPair issueAuthenticationTokens(UserPrincipal principal) {
        Instant now = jwtService.now();
        revokeAll(principal.id(), TokenType.ACCESS);
        revokeAll(principal.id(), TokenType.REFRESH);
        String access = createToken(principal, TokenType.ACCESS, accessTtl, now);
        String refresh = createToken(principal, TokenType.REFRESH, refreshTtl, now);
        return new TokenPair(access, refresh);
    }

    public String createMfaChallenge(UserPrincipal principal) {
        Instant now = jwtService.now();
        revokeAll(principal.id(), TokenType.MFA_CHALLENGE);
        return createToken(principal, TokenType.MFA_CHALLENGE, mfaTtl, now);
    }

    public UUID validateToken(String token, TokenType expectedType) {
        Jws<Claims> claimsJws;
        try {
            claimsJws = jwtService.parse(token);
        } catch (Exception ex) {
            throw new UnauthorizedException("Invalid token");
        }
        Claims claims = claimsJws.getBody();
        if (!expectedType.name().equals(claims.get("type", String.class))) {
            throw new UnauthorizedException("Invalid token type");
        }
        Instant now = jwtService.now();
        var stored = tokenRepository.findActiveToken(token, expectedType, now)
                .orElseThrow(() -> new UnauthorizedException("Token revoked or expired"));
        if (stored.expiresAt().isBefore(now)) {
            throw new UnauthorizedException("Token expired");
        }
        return UUID.fromString(claims.getSubject());
    }

    public void revokeToken(String token) {
        tokenRepository.revokeByToken(token);
    }

    public void revokeAll(UUID userId, TokenType type) {
        tokenRepository.revokeAllActiveTokens(userId, type);
    }

    private String createToken(UserPrincipal principal, TokenType type, Duration ttl, Instant issuedAt) {
        Instant expiresAt = issuedAt.plus(ttl);
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", type.name());
        claims.put("roles", roles(principal));
        claims.put("mfa", principal.isMfaEnabled());
        String token = jwtService.generateToken(principal.id().toString(), expiresAt, claims);
        JwtToken jwtToken = new JwtToken(
                UUID.randomUUID(),
                principal.id(),
                token,
                type,
                issuedAt,
                expiresAt,
                false,
                issuedAt
        );
        tokenRepository.save(jwtToken);
        return token;
    }

    private List<String> roles(UserPrincipal principal) {
        return principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
    }

    public record TokenPair(String accessToken, String refreshToken) {
    }
}
