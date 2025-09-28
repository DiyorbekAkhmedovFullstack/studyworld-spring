package com.studyworld.token.repository;

import com.studyworld.token.model.JwtToken;
import com.studyworld.token.model.TokenType;
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
public class JdbcJwtTokenRepository implements JwtTokenRepository {

    private final JdbcTemplate jdbcTemplate;

    private static final RowMapper<JwtToken> TOKEN_ROW_MAPPER = JdbcJwtTokenRepository::mapToken;

    public JdbcJwtTokenRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public void save(JwtToken token) {
        jdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO jwt_tokens (id, user_id, token, token_type, issued_at, expires_at, revoked, created_at) "
                            + "VALUES (?,?,?,?,?,?,?,?)"
            );
            ps.setObject(1, token.id());
            ps.setObject(2, token.userId());
            ps.setString(3, token.token());
            ps.setString(4, token.type().name());
            ps.setTimestamp(5, Timestamp.from(token.issuedAt()));
            ps.setTimestamp(6, Timestamp.from(token.expiresAt()));
            ps.setBoolean(7, token.revoked());
            ps.setTimestamp(8, Timestamp.from(token.createdAt()));
            return ps;
        });
    }

    @Override
    public void revokeByToken(String token) {
        jdbcTemplate.update("UPDATE jwt_tokens SET revoked = true WHERE token = ?", token);
    }

    @Override
    public void revokeAllActiveTokens(UUID userId, TokenType type) {
        jdbcTemplate.update(
                "UPDATE jwt_tokens SET revoked = true WHERE user_id = ? AND token_type = ? AND revoked = false",
                userId,
                type.name()
        );
    }

    @Override
    public Optional<JwtToken> findActiveToken(String token, TokenType type, Instant now) {
        var tokens = jdbcTemplate.query(
                "SELECT id, user_id, token, token_type, issued_at, expires_at, revoked, created_at FROM jwt_tokens "
                        + "WHERE token = ? AND token_type = ? AND revoked = false AND expires_at > ?",
                TOKEN_ROW_MAPPER,
                token,
                type.name(),
                Timestamp.from(now)
        );
        return tokens.stream().findFirst();
    }

    private static JwtToken mapToken(ResultSet rs, int rowNum) throws SQLException {
        return new JwtToken(
                rs.getObject("id", UUID.class),
                rs.getObject("user_id", UUID.class),
                rs.getString("token"),
                TokenType.valueOf(rs.getString("token_type")),
                rs.getTimestamp("issued_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getBoolean("revoked"),
                rs.getTimestamp("created_at").toInstant()
        );
    }
}
