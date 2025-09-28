package com.studyworld.mfa.service;

import com.studyworld.mfa.dto.MfaSetupResponse;
import java.util.UUID;

public interface MfaService {

    MfaSetupResponse initiateSetup(UUID userId, String email);

    boolean verifyCode(UUID userId, String code);

    void disableMfa(UUID userId);
}
