package com.studyworld.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegistrationRequest(
        @NotBlank @Size(max = 100) String firstName,
        @NotBlank @Size(max = 100) String lastName,
        @Email @NotBlank String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        @Size(max = 30) String phone
) {
}
