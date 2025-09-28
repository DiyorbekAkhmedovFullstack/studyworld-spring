package com.studyworld.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record MfaVerificationRequest(
        @NotBlank String mfaToken,
        @NotBlank @Pattern(regexp = "^[0-9]{6}$") String code
) {
}
