package com.studyworld.auth.service;

import com.studyworld.auth.dto.LoginRequest;
import com.studyworld.auth.dto.LoginResponse;
import com.studyworld.auth.dto.MfaVerificationRequest;
import com.studyworld.auth.dto.PasswordResetConfirmRequest;
import com.studyworld.auth.dto.PasswordResetRequest;
import com.studyworld.auth.dto.RegistrationRequest;
import com.studyworld.auth.dto.ResendVerificationRequest;
import com.studyworld.auth.dto.TokenRefreshRequest;
import com.studyworld.auth.dto.AuthenticatedUser;

public interface AuthService {

    void register(RegistrationRequest request);

    void verify(String tokenId);

    void resendVerification(ResendVerificationRequest request);

    LoginResponse authenticate(LoginRequest request);

    LoginResponse verifyMfa(MfaVerificationRequest request);

    LoginResponse refresh(TokenRefreshRequest request);

    void logout(String accessToken);

    void initiatePasswordReset(PasswordResetRequest request);

    void confirmPasswordReset(PasswordResetConfirmRequest request);

    AuthenticatedUser me();
}
