package com.studyworld.mfa.dto;

public record MfaSetupResponse(
        String qrImage,
        String secret
) {
}
