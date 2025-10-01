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
import com.studyworld.common.exception.BadRequestException;
import com.studyworld.config.JwtProperties;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtProperties jwtProperties;

    public AuthController(AuthService authService, JwtProperties jwtProperties) {
        this.authService = authService;
        this.jwtProperties = jwtProperties;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegistrationRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        LoginResponse response = authService.authenticate(request);
        // Only set cookie when fully authenticated (no MFA step)
        if (!response.mfaRequired() && response.refreshToken() != null) {
            ResponseCookie cookie = buildRefreshCookie(response.refreshToken(), httpRequest);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<LoginResponse> verifyMfa(@Valid @RequestBody MfaVerificationRequest request, HttpServletRequest httpRequest) {
        LoginResponse response = authService.verifyMfa(request);
        if (response.refreshToken() != null) {
            ResponseCookie cookie = buildRefreshCookie(response.refreshToken(), httpRequest);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue(value = "refresh_token", required = false) String refreshCookie,
            @RequestBody(required = false) TokenRefreshRequest request,
            HttpServletRequest httpRequest
    ) {
        String candidate = request != null ? request.refreshToken() : null;
        String token = (candidate != null && !candidate.isBlank()) ? candidate : refreshCookie;
        if (token == null || token.isBlank()) {
            throw new BadRequestException("Refresh token required");
        }
        LoginResponse response = authService.refresh(new TokenRefreshRequest(token));
        if (response.refreshToken() != null) {
            ResponseCookie cookie = buildRefreshCookie(response.refreshToken(), httpRequest);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader, HttpServletRequest httpRequest) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            authService.logout(token);
        }
        // Clear refresh cookie
        ResponseCookie cleared = clearRefreshCookie(httpRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .build();
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

    private ResponseCookie buildRefreshCookie(String refreshToken, HttpServletRequest request) {
        boolean secure = isSecure(request);
        // Use None for cross-site when secure, otherwise fall back to Lax for local dev
        String sameSite = secure ? "None" : "Lax";
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path("/api/auth")
                .maxAge(jwtProperties.refreshTokenTtl())
                .build();
    }

    private ResponseCookie clearRefreshCookie(HttpServletRequest request) {
        boolean secure = isSecure(request);
        String sameSite = secure ? "None" : "Lax";
        return ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path("/api/auth")
                .maxAge(0)
                .build();
    }

    private boolean isSecure(HttpServletRequest request) {
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (forwardedProto != null && !forwardedProto.isBlank()) {
            String first = forwardedProto.split(",")[0].trim();
            if ("https".equalsIgnoreCase(first)) {
                return true;
            }
        }
        String forwardedSsl = request.getHeader("X-Forwarded-Ssl");
        if ("on".equalsIgnoreCase(forwardedSsl)) {
            return true;
        }
        String forwardedScheme = request.getHeader("X-Forwarded-Scheme");
        if ("https".equalsIgnoreCase(forwardedScheme)) {
            return true;
        }
        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null && forwarded.toLowerCase().contains("proto=https")) {
            return true;
        }
        return request.isSecure();
    }
}
