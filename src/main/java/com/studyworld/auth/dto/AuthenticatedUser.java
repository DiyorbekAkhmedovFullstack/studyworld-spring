package com.studyworld.auth.dto;

import com.studyworld.user.model.UserRole;
import java.util.Set;
import java.util.UUID;

public record AuthenticatedUser(
        UUID id,
        String email,
        String firstName,
        String lastName,
        boolean mfaEnabled,
        Set<UserRole> roles
) {
}
