package com.studyworld.user.service;

import com.studyworld.common.exception.ResourceNotFoundException;
import com.studyworld.user.model.User;
import com.studyworld.user.repository.UserRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultUserService implements UserService {

    private final UserRepository userRepository;

    public DefaultUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @Override
    @Transactional
    public UUID create(User user) {
        return userRepository.create(user);
    }

    @Override
    public void enable(UUID userId) {
        userRepository.enableUser(userId);
    }

    @Override
    public void markEmailVerified(UUID userId) {
        userRepository.markEmailVerified(userId);
    }

    @Override
    public void updatePassword(UUID userId, String passwordHash, Instant passwordUpdatedAt, Instant passwordExpiresAt) {
        userRepository.updatePassword(userId, passwordHash, passwordUpdatedAt, passwordExpiresAt);
    }

    @Override
    public void updateLockout(UUID userId, int failedAttempts, Instant lockoutUntil) {
        userRepository.updateLockout(userId, failedAttempts, lockoutUntil);
    }

    @Override
    public void resetFailedAttempts(UUID userId) {
        userRepository.resetFailedAttempts(userId);
    }

    @Override
    public void updateProfile(UUID userId, String firstName, String lastName, String phone, String profilePictureUrl) {
        userRepository.updateProfile(userId, firstName, lastName, phone, profilePictureUrl);
    }

    @Override
    public void updateMfaSecret(UUID userId, String secret, boolean enabled) {
        userRepository.updateMfaSecret(userId, secret, enabled);
    }
}
