package com.studyworld.token.repository;

import com.studyworld.token.model.PasswordResetToken;
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
public class JdbcPasswordResetTokenRepository implements PasswordResetTokenRepository {

    private final JdbcTemplate jdbcTemplate;
    private static final RowMapper<PasswordResetToken> ROW_MAPPER = JdbcPasswordResetTokenRepository::map;

    public JdbcPasswordResetTokenRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public PasswordResetToken create(UUID userId, Instant expiresAt) {
        UUID tokenId = UUID.randomUUID();
        Instant now = Instant.now();
        jdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO password_reset_tokens (token, user_id, expires_at, consumed, created_at) VALUES (?,?,?,?,?)"
            );
            ps.setObject(1, tokenId);
            ps.setObject(2, userId);
            ps.setTimestamp(3, Timestamp.from(expiresAt));
            ps.setBoolean(4, false);
            ps.setTimestamp(5, Timestamp.from(now));
            return ps;
        });
        return new PasswordResetToken(tokenId, userId, expiresAt, false, now);
    }

    @Override
    public Optional<PasswordResetToken> find(UUID tokenId) {
        var tokens = jdbcTemplate.query(
                "SELECT token, user_id, expires_at, consumed, created_at FROM password_reset_tokens WHERE token = ?",
                ROW_MAPPER,
                tokenId
        );
        return tokens.stream().findFirst();
    }

    @Override
    public void markConsumed(UUID tokenId) {
        jdbcTemplate.update("UPDATE password_reset_tokens SET consumed = true WHERE token = ?", tokenId);
    }

    private static PasswordResetToken map(ResultSet rs, int rowNum) throws SQLException {
        return new PasswordResetToken(
                rs.getObject("token", UUID.class),
                rs.getObject("user_id", UUID.class),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getBoolean("consumed"),
                rs.getTimestamp("created_at").toInstant()
        );
    }
}
