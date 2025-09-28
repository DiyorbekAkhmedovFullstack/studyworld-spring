package com.studyworld.profile.service;

import com.studyworld.auth.service.UserPrincipal;
import com.studyworld.common.exception.UnauthorizedException;
import com.studyworld.common.mapper.UserMapper;
import com.studyworld.config.AppProperties;
import com.studyworld.profile.dto.PasswordChangeRequest;
import com.studyworld.profile.dto.ProfilePictureUpdateRequest;
import com.studyworld.profile.dto.ProfileResponse;
import com.studyworld.profile.dto.ProfileUpdateRequest;
import com.studyworld.user.model.User;
import com.studyworld.user.service.UserService;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class DefaultProfileService implements ProfileService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties appProperties;

    public DefaultProfileService(UserService userService, PasswordEncoder passwordEncoder, AppProperties appProperties) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.appProperties = appProperties;
    }

    @Override
    public ProfileResponse getCurrentProfile() {
        User user = currentUser();
        return UserMapper.toProfileResponse(user);
    }

    @Override
    public ProfileResponse updateProfile(ProfileUpdateRequest request) {
        UserPrincipal principal = currentPrincipal();
        User current = userService.findById(principal.id());
        userService.updateProfile(principal.id(), request.firstName(), request.lastName(), request.phone(), current.profilePictureUrl());
        User updated = userService.findById(principal.id());
        return UserMapper.toProfileResponse(updated);
    }

    @Override
    public void updatePassword(PasswordChangeRequest request) {
        User user = currentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.passwordHash())) {
            throw new UnauthorizedException("Current password is incorrect");
        }
        Instant now = Instant.now();
        var security = securityProperties();
        userService.updatePassword(user.id(), passwordEncoder.encode(request.newPassword()), now, now.plus(security.passwordExpiry()));
    }

    @Override
    public ProfileResponse updateProfilePicture(ProfilePictureUpdateRequest request) {
        UserPrincipal principal = currentPrincipal();
        User current = userService.findById(principal.id());
        userService.updateProfile(principal.id(), current.firstName(), current.lastName(), current.phone(), request.profilePictureUrl());
        User updated = userService.findById(principal.id());
        return UserMapper.toProfileResponse(updated);
    }

    private User currentUser() {
        UserPrincipal principal = currentPrincipal();
        return userService.findById(principal.id());
    }

    private UserPrincipal currentPrincipal() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof UserPrincipal principal)) {
            throw new UnauthorizedException("Unauthenticated");
        }
        return principal;
    }

    private AppProperties.SecurityProperties securityProperties() {
        AppProperties.SecurityProperties security = appProperties.security();
        if (security == null) {
            return new AppProperties.SecurityProperties(6, Duration.ofMinutes(15), Duration.ofDays(90));
        }
        Duration expiry = security.passwordExpiry() != null ? security.passwordExpiry() : Duration.ofDays(90);
        return new AppProperties.SecurityProperties(
                security.maxFailedAttempts() > 0 ? security.maxFailedAttempts() : 6,
                security.lockoutDuration() != null ? security.lockoutDuration() : Duration.ofMinutes(15),
                expiry
        );
    }
}
