package com.studyworld.common.mapper;

import com.studyworld.auth.dto.AuthenticatedUser;
import com.studyworld.profile.dto.ProfileResponse;
import com.studyworld.user.model.User;

public final class UserMapper {

    private UserMapper() {
    }

    public static AuthenticatedUser toAuthenticatedUser(User user) {
        return new AuthenticatedUser(
                user.id(),
                user.email(),
                user.firstName(),
                user.lastName(),
                user.mfaEnabled(),
                user.roles()
        );
    }

    public static ProfileResponse toProfileResponse(User user) {
        return new ProfileResponse(
                user.id(),
                user.email(),
                user.firstName(),
                user.lastName(),
                user.phone(),
                user.mfaEnabled(),
                user.profilePictureUrl(),
                user.roles()
        );
    }
}
