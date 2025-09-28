package com.studyworld.profile.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
        @NotBlank @Size(min = 8, max = 128) String currentPassword,
        @NotBlank @Size(min = 12, max = 128) String newPassword
) {
}
