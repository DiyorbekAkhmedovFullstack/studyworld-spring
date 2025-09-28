package com.studyworld.user.service;

import com.studyworld.user.model.User;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface UserService {

    Optional<User> findByEmail(String email);

    User findById(UUID id);

    UUID create(User user);

    void enable(UUID userId);

    void markEmailVerified(UUID userId);

    void updatePassword(UUID userId, String passwordHash, Instant passwordUpdatedAt, Instant passwordExpiresAt);

    void updateLockout(UUID userId, int failedAttempts, Instant lockoutUntil);

    void resetFailedAttempts(UUID userId);

    void updateProfile(UUID userId, String firstName, String lastName, String phone, String profilePictureUrl);

    void updateMfaSecret(UUID userId, String secret, boolean enabled);
}
