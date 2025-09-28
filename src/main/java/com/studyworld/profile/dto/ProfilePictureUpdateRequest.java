package com.studyworld.profile.dto;

import jakarta.validation.constraints.NotBlank;

public record ProfilePictureUpdateRequest(@NotBlank String profilePictureUrl) {
}
