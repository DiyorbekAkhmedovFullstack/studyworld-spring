package com.studyworld.user.repository;

import com.studyworld.user.model.User;
import com.studyworld.user.model.UserRole;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcUserRepository implements UserRepository {

    private final JdbcTemplate jdbcTemplate;
    public JdbcUserRepository(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    private static final RowMapper<User> USER_ROW_MAPPER = (rs, rowNum) -> mapUser(rs);

    @Override
    public Optional<User> findByEmail(String email) {
        var users = jdbcTemplate.query(
                "SELECT id, email, password_hash, first_name, last_name, phone, enabled, email_verified, mfa_enabled, "
                        + "mfa_secret, failed_attempts, lockout_until, password_updated_at, password_expires_at, profile_picture_url, "
                        + "created_at, updated_at FROM users WHERE lower(email) = lower(?)",
                USER_ROW_MAPPER,
                email
        );
        return users.stream().findFirst().map(this::attachRoles);
    }

    @Override
    public Optional<User> findById(UUID id) {
        var users = jdbcTemplate.query(
                "SELECT id, email, password_hash, first_name, last_name, phone, enabled, email_verified, mfa_enabled, "
                        + "mfa_secret, failed_attempts, lockout_until, password_updated_at, password_expires_at, profile_picture_url, "
                        + "created_at, updated_at FROM users WHERE id = ?",
                USER_ROW_MAPPER,
                id
        );
        return users.stream().findFirst().map(this::attachRoles);
    }

    @Override
    public UUID create(User user) {
        UUID userId = user.id() != null ? user.id() : UUID.randomUUID();
        jdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO users (id, email, password_hash, first_name, last_name, phone, enabled, email_verified, mfa_enabled, "
                            + "mfa_secret, failed_attempts, lockout_until, password_updated_at, password_expires_at, profile_picture_url, created_at, updated_at) "
                            + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            );
            ps.setObject(1, userId);
            ps.setString(2, user.email());
            ps.setString(3, user.passwordHash());
            ps.setString(4, user.firstName());
            ps.setString(5, user.lastName());
            ps.setString(6, user.phone());
            ps.setBoolean(7, user.enabled());
            ps.setBoolean(8, user.emailVerified());
            ps.setBoolean(9, user.mfaEnabled());
            ps.setString(10, user.mfaSecret());
            ps.setInt(11, user.failedAttempts());
            setTimestamp(ps, 12, user.lockoutUntil());
            setTimestamp(ps, 13, user.passwordUpdatedAt());
            setTimestamp(ps, 14, user.passwordExpiresAt());
            ps.setString(15, user.profilePictureUrl());
            setTimestamp(ps, 16, user.createdAt());
            setTimestamp(ps, 17, user.updatedAt());
            return ps;
        });
        updateRoles(userId, toRoleNames(user.roles()));
        return userId;
    }

    @Override
    public void updateRoles(UUID userId, Set<String> roles) {
        jdbcTemplate.update("DELETE FROM user_roles WHERE user_id = ?", userId);
        if (roles == null || roles.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate(
                "INSERT INTO user_roles (user_id, role) VALUES (?,?)",
                roles.stream().map(role -> new Object[]{userId, role}).toList()
        );
    }

    @Override
    public void enableUser(UUID userId) {
        jdbcTemplate.update("UPDATE users SET enabled = true, updated_at = now() WHERE id = ?", userId);
    }

    @Override
    public void markEmailVerified(UUID userId) {
        jdbcTemplate.update("UPDATE users SET email_verified = true, updated_at = now() WHERE id = ?", userId);
    }

    @Override
    public void updatePassword(UUID userId, String passwordHash, Instant passwordUpdatedAt, Instant passwordExpiresAt) {
        jdbcTemplate.update(
                "UPDATE users SET password_hash = ?, password_updated_at = ?, password_expires_at = ?, updated_at = now() WHERE id = ?",
                passwordHash,
                Timestamp.from(passwordUpdatedAt),
                Timestamp.from(passwordExpiresAt),
                userId
        );
    }

    @Override
    public void updateLockout(UUID userId, int failedAttempts, Instant lockoutUntil) {
        jdbcTemplate.update(
                "UPDATE users SET failed_attempts = ?, lockout_until = ?, updated_at = now() WHERE id = ?",
                failedAttempts,
                lockoutUntil == null ? null : Timestamp.from(lockoutUntil),
                userId
        );
    }

    @Override
    public void resetFailedAttempts(UUID userId) {
        jdbcTemplate.update(
                "UPDATE users SET failed_attempts = 0, lockout_until = NULL, updated_at = now() WHERE id = ?",
                userId
        );
    }

    @Override
    public void updateProfile(UUID userId, String firstName, String lastName, String phone, String profilePictureUrl) {
        jdbcTemplate.update(
                "UPDATE users SET first_name = ?, last_name = ?, phone = ?, profile_picture_url = ?, updated_at = now() WHERE id = ?",
                firstName,
                lastName,
                phone,
                profilePictureUrl,
                userId
        );
    }

    @Override
    public void updateMfaSecret(UUID userId, String secret, boolean enabled) {
        jdbcTemplate.update(
                "UPDATE users SET mfa_secret = ?, mfa_enabled = ?, updated_at = now() WHERE id = ?",
                secret,
                enabled,
                userId
        );
    }

    private User attachRoles(User user) {
        var roles = fetchRoles(user.id());
        return new User(
                user.id(),
                user.email(),
                user.passwordHash(),
                user.firstName(),
                user.lastName(),
                user.phone(),
                user.enabled(),
                user.emailVerified(),
                user.mfaEnabled(),
                user.mfaSecret(),
                user.failedAttempts(),
                user.lockoutUntil(),
                user.passwordUpdatedAt(),
                user.passwordExpiresAt(),
                user.profilePictureUrl(),
                user.createdAt(),
                user.updatedAt(),
                roles
        );
    }

    private Set<UserRole> fetchRoles(UUID userId) {
        var rows = jdbcTemplate.query(
                "SELECT role FROM user_roles WHERE user_id = ?",
                (rs, rowNum) -> rs.getString("role"),
                userId
        );
        if (rows.isEmpty()) {
            return Collections.emptySet();
        }
        EnumSet<UserRole> roles = EnumSet.noneOf(UserRole.class);
        for (String role : rows) {
            roles.add(UserRole.valueOf(role));
        }
        return roles;
    }

    private static Set<String> toRoleNames(Set<UserRole> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> names = new HashSet<>();
        for (UserRole role : roles) {
            names.add(role.name());
        }
        return names;
    }

    private static User mapUser(ResultSet rs) throws SQLException {
        return new User(
                rs.getObject("id", UUID.class),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("phone"),
                rs.getBoolean("enabled"),
                rs.getBoolean("email_verified"),
                rs.getBoolean("mfa_enabled"),
                rs.getString("mfa_secret"),
                rs.getInt("failed_attempts"),
                getInstant(rs, "lockout_until"),
                getInstant(rs, "password_updated_at"),
                getInstant(rs, "password_expires_at"),
                rs.getString("profile_picture_url"),
                getInstant(rs, "created_at"),
                getInstant(rs, "updated_at"),
                Collections.emptySet()
        );
    }

    private static Instant getInstant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private static void setTimestamp(PreparedStatement ps, int index, Instant instant) throws SQLException {
        if (instant == null) {
            ps.setTimestamp(index, null);
        } else {
            ps.setTimestamp(index, Timestamp.from(instant));
        }
    }
}
