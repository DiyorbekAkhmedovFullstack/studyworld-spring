package com.studyworld.mfa.service;

import com.studyworld.config.AppProperties;
import com.studyworld.mfa.dto.MfaSetupResponse;
import com.studyworld.user.model.User;
import com.studyworld.user.service.UserService;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.TimeProvider;
import java.util.Base64;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TotpMfaService implements MfaService {

    private static final Logger log = LoggerFactory.getLogger(TotpMfaService.class);

    private final UserService userService;
    private final AppProperties appProperties;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final DefaultCodeVerifier codeVerifier;

    public TotpMfaService(UserService userService, AppProperties appProperties) {
        this.userService = userService;
        this.appProperties = appProperties;
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        TimeProvider timeProvider = () -> System.currentTimeMillis() / 1000L;
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        this.codeVerifier.setAllowedTimePeriodDiscrepancy(1);
    }

    @Override
    public MfaSetupResponse initiateSetup(UUID userId, String email) {
        String secret = secretGenerator.generate();
        userService.updateMfaSecret(userId, secret, false);
        try {
            String dataUri = buildQrCode(secret, email);
            return new MfaSetupResponse(dataUri, secret);
        } catch (QrGenerationException ex) {
            log.error("Failed to generate QR code for user {}", userId, ex);
            throw new IllegalStateException("Unable to generate QR code");
        }
    }

    @Override
    public boolean verifyCode(UUID userId, String code) {
        User user = userService.findById(userId);
        if (user.mfaSecret() == null) {
            return false;
        }
        boolean valid = codeVerifier.isValidCode(user.mfaSecret(), code);
        if (valid) {
            userService.updateMfaSecret(userId, user.mfaSecret(), true);
        }
        return valid;
    }

    @Override
    public void disableMfa(UUID userId) {
        userService.updateMfaSecret(userId, null, false);
    }

    private String buildQrCode(String secret, String email) throws QrGenerationException {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer(appProperties.mfa().issuer())
                .build();
        byte[] image = qrGenerator.generate(data);
        String base64 = Base64.getEncoder().encodeToString(image);
        return "data:" + qrGenerator.getImageMimeType() + ";base64," + base64;
    }
}
