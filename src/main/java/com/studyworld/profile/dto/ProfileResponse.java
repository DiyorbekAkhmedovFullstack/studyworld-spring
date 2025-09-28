package com.studyworld.profile.dto;

import com.studyworld.user.model.UserRole;
import java.util.Set;
import java.util.UUID;

public record ProfileResponse(
        UUID id,
        String email,
        String firstName,
        String lastName,
        String phone,
        boolean mfaEnabled,
        String profilePictureUrl,
        Set<UserRole> roles
) {
}
