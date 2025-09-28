package com.studyworld.token.repository;

import com.studyworld.token.model.VerificationToken;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcVerificationTokenRepository implements VerificationTokenRepository {

    private final JdbcTemplate jdbcTemplate;
    private static final RowMapper<VerificationToken> ROW_MAPPER = JdbcVerificationTokenRepository::map;

    public JdbcVerificationTokenRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public VerificationToken create(UUID userId, Instant expiresAt) {
        UUID tokenId = UUID.randomUUID();
        Instant now = Instant.now();
        jdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO verification_tokens (token, user_id, expires_at, consumed, created_at) VALUES (?,?,?,?,?)"
            );
            ps.setObject(1, tokenId);
            ps.setObject(2, userId);
            ps.setTimestamp(3, Timestamp.from(expiresAt));
            ps.setBoolean(4, false);
            ps.setTimestamp(5, Timestamp.from(now));
            return ps;
        });
        return new VerificationToken(tokenId, userId, expiresAt, false, now);
    }

    @Override
    public Optional<VerificationToken> find(UUID tokenId) {
        var tokens = jdbcTemplate.query(
                "SELECT token, user_id, expires_at, consumed, created_at FROM verification_tokens WHERE token = ?",
                ROW_MAPPER,
                tokenId
        );
        return tokens.stream().findFirst();
    }

    @Override
    public void markConsumed(UUID tokenId) {
        jdbcTemplate.update("UPDATE verification_tokens SET consumed = true WHERE token = ?", tokenId);
    }

    private static VerificationToken map(ResultSet rs, int rowNum) throws SQLException {
        return new VerificationToken(
                rs.getObject("token", UUID.class),
                rs.getObject("user_id", UUID.class),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getBoolean("consumed"),
                rs.getTimestamp("created_at").toInstant()
        );
    }
}
