package com.studyworld.auth.dto;

public record LoginResponse(
        boolean mfaRequired,
        AuthenticatedUser user,
        String accessToken,
        String refreshToken,
        String mfaToken
) {
    public static LoginResponse pendingMfa(AuthenticatedUser user, String challengeToken) {
        return new LoginResponse(true, user, null, null, challengeToken);
    }

    public static LoginResponse authenticated(AuthenticatedUser user, String accessToken, String refreshToken) {
        return new LoginResponse(false, user, accessToken, refreshToken, null);
    }
}
