package com.studyworld.token.service;

import com.studyworld.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtProperties properties;
    private final Clock clock;
    private Key signingKey;

    @Autowired
    public JwtService(JwtProperties properties) {
        this(properties, Clock.systemUTC());
    }

    private JwtService(JwtProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public JwtProperties getProperties() {
        return properties;
    }

    public String generateToken(String subject, Instant expiresAt, Map<String, Object> claims) {
        Instant issuedAt = clock.instant();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer(properties.issuer())
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiresAt))
                .signWith(signingKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey())
                .build()
                .parseClaimsJws(token);
    }

    public Instant now() {
        return clock.instant();
    }

    private Key signingKey() {
        if (signingKey == null) {
            if (properties.secret() == null || properties.secret().isBlank()) {
                throw new IllegalStateException("JWT secret must be configured");
            }
            byte[] keyBytes = Decoders.BASE64.decode(properties.secret());
            signingKey = Keys.hmacShaKeyFor(keyBytes);
        }
        return signingKey;
    }
}
