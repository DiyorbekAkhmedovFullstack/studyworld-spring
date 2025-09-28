package com.studyworld.auth.web;

import com.studyworld.auth.dto.AuthenticatedUser;
import com.studyworld.auth.dto.LoginRequest;
import com.studyworld.auth.dto.LoginResponse;
import com.studyworld.auth.dto.MfaVerificationRequest;
import com.studyworld.auth.dto.PasswordResetConfirmRequest;
import com.studyworld.auth.dto.PasswordResetRequest;
import com.studyworld.auth.dto.RegistrationRequest;
import com.studyworld.auth.dto.ResendVerificationRequest;
import com.studyworld.auth.dto.TokenRefreshRequest;
import com.studyworld.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegistrationRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.authenticate(request);
    }

    @PostMapping("/mfa/verify")
    public LoginResponse verifyMfa(@Valid @RequestBody MfaVerificationRequest request) {
        return authService.verifyMfa(request);
    }

    @PostMapping("/refresh")
    public LoginResponse refresh(@Valid @RequestBody TokenRefreshRequest request) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            authService.logout(token);
        }
        return ResponseEntity.ok().build();
    }

    @GetMapping("/verify")
    public ResponseEntity<Void> verify(@RequestParam("token") String token) {
        authService.verify(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        authService.resendVerification(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password-reset/request")
    public ResponseEntity<Void> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        authService.initiatePasswordReset(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Void> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
        authService.confirmPasswordReset(request);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public AuthenticatedUser me() {
        return authService.me();
    }
}
