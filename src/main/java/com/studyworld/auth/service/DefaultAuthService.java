package com.studyworld.auth.service;

import com.studyworld.auth.dto.AuthenticatedUser;
import com.studyworld.auth.dto.LoginRequest;
import com.studyworld.auth.dto.LoginResponse;
import com.studyworld.auth.dto.MfaVerificationRequest;
import com.studyworld.auth.dto.PasswordResetConfirmRequest;
import com.studyworld.auth.dto.PasswordResetRequest;
import com.studyworld.auth.dto.RegistrationRequest;
import com.studyworld.auth.dto.ResendVerificationRequest;
import com.studyworld.auth.dto.TokenRefreshRequest;
import com.studyworld.common.exception.BadRequestException;
import com.studyworld.common.exception.ConflictException;
import com.studyworld.common.exception.ResourceNotFoundException;
import com.studyworld.common.exception.UnauthorizedException;
import com.studyworld.common.mapper.UserMapper;
import com.studyworld.config.AppProperties;
import com.studyworld.mail.service.MailService;
import com.studyworld.mail.template.EmailTemplates;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import com.studyworld.mfa.service.MfaService;
import com.studyworld.token.model.TokenType;
import com.studyworld.token.repository.PasswordResetTokenRepository;
import com.studyworld.token.repository.VerificationTokenRepository;
import com.studyworld.token.service.TokenService;
import com.studyworld.token.service.TokenService.TokenPair;
import com.studyworld.user.model.User;
import com.studyworld.user.model.UserRole;
import com.studyworld.user.service.UserService;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class DefaultAuthService implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthService.class);

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final MailService mailService;
    private final AppProperties appProperties;
    private final MfaService mfaService;
    private final EmailTemplates emailTemplates;
    private final MessageSource messages;

    public DefaultAuthService(UserService userService,
                              PasswordEncoder passwordEncoder,
                              VerificationTokenRepository verificationTokenRepository,
                              PasswordResetTokenRepository passwordResetTokenRepository,
                              TokenService tokenService,
                              AuthenticationManager authenticationManager,
                              MailService mailService,
                              AppProperties appProperties,
                              MfaService mfaService,
                              EmailTemplates emailTemplates,
                              MessageSource messages) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.verificationTokenRepository = verificationTokenRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.mailService = mailService;
        this.appProperties = appProperties;
        this.mfaService = mfaService;
        this.emailTemplates = emailTemplates;
        this.messages = messages;
    }

    @Override
    @Transactional
    public void register(RegistrationRequest request) {
        userService.findByEmail(request.email()).ifPresent(user -> {
            throw new ConflictException("Email already registered");
        });
        Instant now = Instant.now();
        var security = securityProperties();
        Instant passwordExpiry = now.plus(security.passwordExpiry());
        User user = new User(
                UUID.randomUUID(),
                request.email().toLowerCase(),
                passwordEncoder.encode(request.password()),
                request.firstName(),
                request.lastName(),
                request.phone(),
                false,
                false,
                false,
                null,
                0,
                null,
                now,
                passwordExpiry,
                null,
                now,
                now,
                Set.of(UserRole.USER)
        );
        UUID userId = userService.create(user);
        var token = verificationTokenRepository.create(userId, now.plus(verificationTtl()));
        sendVerificationMail(user.email(), token.token());
        log.info("Created user {} pending verification", user.email());
    }

    @Override
    public void verify(String tokenId) {
        UUID verificationId = parseToken(tokenId);
        var token = verificationTokenRepository.find(verificationId)
                .orElseThrow(() -> new BadRequestException("Verification token not found"));
        Instant now = Instant.now();
        if (!token.isActive(now)) {
            throw new BadRequestException("Verification token expired or already used");
        }
        verificationTokenRepository.markConsumed(token.token());
        userService.markEmailVerified(token.userId());
        userService.enable(token.userId());
        log.info("User {} verified email", token.userId());
    }

    @Override
    public void resendVerification(ResendVerificationRequest request) {
        User user = userService.findByEmail(request.email())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (user.emailVerified()) {
            throw new BadRequestException("Account already verified");
        }
        var token = verificationTokenRepository.create(user.id(), Instant.now().plus(verificationTtl()));
        sendVerificationMail(user.email(), token.token());
    }

    @Override
    public LoginResponse authenticate(LoginRequest request) {
        User user = userService.findByEmail(request.email())
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
        Instant now = Instant.now();
        if (!user.emailVerified()) {
            throw new UnauthorizedException("Account not verified");
        }
        if (!user.enabled()) {
            throw new UnauthorizedException("Account disabled");
        }
        if (user.isLocked(now)) {
            throw new UnauthorizedException("Account locked. Try again later");
        }
        try {
            Authentication authentication = new UsernamePasswordAuthenticationToken(request.email(), request.password());
            authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException ex) {
            handleFailedAttempt(user);
            throw new UnauthorizedException("Invalid credentials");
        }
        userService.resetFailedAttempts(user.id());
        if (user.isPasswordExpired(now)) {
            throw new UnauthorizedException("Password expired");
        }
        UserPrincipal principal = new UserPrincipal(user);
        AuthenticatedUser authUser = UserMapper.toAuthenticatedUser(user);
        if (user.mfaEnabled()) {
            String challenge = tokenService.createMfaChallenge(principal);
            return LoginResponse.pendingMfa(authUser, challenge);
        }
        TokenPair tokens = tokenService.issueAuthenticationTokens(principal);
        return LoginResponse.authenticated(authUser, tokens.accessToken(), tokens.refreshToken());
    }

    @Override
    public LoginResponse verifyMfa(MfaVerificationRequest request) {
        UUID userId = tokenService.validateToken(request.mfaToken(), TokenType.MFA_CHALLENGE);
        tokenService.revokeToken(request.mfaToken());
        if (!mfaService.verifyCode(userId, request.code())) {
            throw new UnauthorizedException("Invalid MFA code");
        }
        User user = userService.findById(userId);
        UserPrincipal principal = new UserPrincipal(user);
        TokenPair tokens = tokenService.issueAuthenticationTokens(principal);
        return LoginResponse.authenticated(UserMapper.toAuthenticatedUser(user), tokens.accessToken(), tokens.refreshToken());
    }

    @Override
    public LoginResponse refresh(TokenRefreshRequest request) {
        UUID userId = tokenService.validateToken(request.refreshToken(), TokenType.REFRESH);
        tokenService.revokeToken(request.refreshToken());
        User user = userService.findById(userId);
        if (!user.enabled() || !user.emailVerified()) {
            throw new UnauthorizedException("Account inactive");
        }
        Instant now = Instant.now();
        if (user.isLocked(now)) {
            throw new UnauthorizedException("Account locked");
        }
        if (user.isPasswordExpired(now)) {
            throw new UnauthorizedException("Password expired");
        }
        UserPrincipal principal = new UserPrincipal(user);
        TokenPair tokens = tokenService.issueAuthenticationTokens(principal);
        return LoginResponse.authenticated(UserMapper.toAuthenticatedUser(user), tokens.accessToken(), tokens.refreshToken());
    }

    @Override
    public void logout(String accessToken) {
        tokenService.revokeToken(accessToken);
    }

    @Override
    public void initiatePasswordReset(PasswordResetRequest request) {
        Optional<User> userOpt = userService.findByEmail(request.email());
        if (userOpt.isEmpty()) {
            return;
        }
        User user = userOpt.get();
        var token = passwordResetTokenRepository.create(user.id(), Instant.now().plus(passwordResetTtl()));
        sendPasswordResetMail(user.email(), token.token());
    }

    @Override
    public void confirmPasswordReset(PasswordResetConfirmRequest request) {
        UUID tokenId = parseToken(request.token());
        var token = passwordResetTokenRepository.find(tokenId)
                .orElseThrow(() -> new BadRequestException("Reset token not found"));
        Instant now = Instant.now();
        if (!token.isActive(now)) {
            throw new BadRequestException("Reset token expired or already used");
        }
        String encoded = passwordEncoder.encode(request.newPassword());
        var security = securityProperties();
        userService.updatePassword(token.userId(), encoded, now, now.plus(security.passwordExpiry()));
        userService.resetFailedAttempts(token.userId());
        passwordResetTokenRepository.markConsumed(token.token());
    }

    @Override
    public AuthenticatedUser me() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof UserPrincipal principal)) {
            throw new UnauthorizedException("Unauthenticated");
        }
        return UserMapper.toAuthenticatedUser(principal.domainUser());
    }

    private void handleFailedAttempt(User user) {
        int attempts = user.failedAttempts() + 1;
        Instant lockoutUntil = null;
        var security = securityProperties();
        if (attempts >= security.maxFailedAttempts()) {
            lockoutUntil = Instant.now().plus(security.lockoutDuration());
            attempts = 0;
        }
        userService.updateLockout(user.id(), attempts, lockoutUntil);
    }

    private UUID parseToken(String tokenId) {
        try {
            return UUID.fromString(tokenId);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Invalid token format");
        }
    }

    private void sendVerificationMail(String email, UUID token) {
        String link = appProperties.frontendUrl() + "/verify#token=" + token;
        var ttl = verificationTtl();
        var locale = LocaleContextHolder.getLocale();
        String ttlText = humanize(ttl, locale);
        String body = emailTemplates.verificationEmail(link, ttlText, locale);
        // Avoid logging raw verification links in production
        log.info("Verification email queued for {}", email);
        String subject = messages.getMessage("email.verify.subject", null, locale);
        mailService.sendHtmlMail(email, subject, body);
    }

    private void sendPasswordResetMail(String email, UUID token) {
        String link = appProperties.frontendUrl() + "/reset-password/confirm#token=" + token;
        var ttl = passwordResetTtl();
        var locale = LocaleContextHolder.getLocale();
        String ttlText = humanize(ttl, locale);
        String body = emailTemplates.passwordResetEmail(link, ttlText, locale);
        // Avoid logging raw reset links in production
        log.info("Password reset email queued for {}", email);
        String subject = messages.getMessage("email.reset.subject", null, locale);
        mailService.sendHtmlMail(email, subject, body);
    }

    private String humanize(Duration d, java.util.Locale locale) {
        long seconds = d.getSeconds();
        long minutes = (seconds + 59) / 60; // round up to next minute
        if ("ru".equalsIgnoreCase(locale.getLanguage())) {
            if (minutes < 60) {
                return ruPlural(minutes, "минута", "минуты", "минут");
            }
            long hours = (minutes + 59) / 60;
            if (hours < 24) {
                return ruPlural(hours, "час", "часа", "часов");
            }
            long days = (hours + 23) / 24;
            return ruPlural(days, "день", "дня", "дней");
        } else {
            if (minutes < 60) {
                return minutes + (minutes == 1 ? " minute" : " minutes");
            }
            long hours = (minutes + 59) / 60;
            if (hours < 24) {
                return hours + (hours == 1 ? " hour" : " hours");
            }
            long days = (hours + 23) / 24;
            return days + (days == 1 ? " day" : " days");
        }
    }

    private String ruPlural(long n, String one, String few, String many) {
        long nAbs = Math.abs(n);
        long mod10 = nAbs % 10;
        long mod100 = nAbs % 100;
        String unit;
        if (mod10 == 1 && mod100 != 11) {
            unit = one;
        } else if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) {
            unit = few;
        } else {
            unit = many;
        }
        return n + " " + unit;
    }

    private AppProperties.SecurityProperties securityProperties() {
        AppProperties.SecurityProperties security = appProperties.security();
        if (security == null) {
            return new AppProperties.SecurityProperties(6, Duration.ofMinutes(15), Duration.ofDays(90));
        }
        int attempts = security.maxFailedAttempts() > 0 ? security.maxFailedAttempts() : 6;
        Duration lockout = security.lockoutDuration() != null ? security.lockoutDuration() : Duration.ofMinutes(15);
        Duration expiry = security.passwordExpiry() != null ? security.passwordExpiry() : Duration.ofDays(90);
        return new AppProperties.SecurityProperties(attempts, lockout, expiry);
    }

    private Duration verificationTtl() {
        Duration ttl = appProperties.verificationTokenTtl();
        return ttl != null ? ttl : Duration.ofHours(1);
    }

    private Duration passwordResetTtl() {
        Duration ttl = appProperties.passwordResetTokenTtl();
        return ttl != null ? ttl : Duration.ofMinutes(30);
    }
}
