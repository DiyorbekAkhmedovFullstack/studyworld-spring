package com.studyworld.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record EnableMfaRequest(@NotBlank @Pattern(regexp = "^[0-9]{6}$") String code) {
}
