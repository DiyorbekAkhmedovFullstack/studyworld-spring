package com.studyworld.mfa.web;

import com.studyworld.auth.service.UserPrincipal;
import com.studyworld.common.exception.UnauthorizedException;
import com.studyworld.common.mapper.UserMapper;
import com.studyworld.mfa.dto.EnableMfaRequest;
import com.studyworld.mfa.dto.MfaSetupResponse;
import com.studyworld.mfa.service.MfaService;
import com.studyworld.profile.dto.ProfileResponse;
import com.studyworld.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/mfa")
public class MfaController {

    private final MfaService mfaService;
    private final UserService userService;

    public MfaController(MfaService mfaService, UserService userService) {
        this.mfaService = mfaService;
        this.userService = userService;
    }

    @PostMapping("/setup")
    public MfaSetupResponse setup() {
        UserPrincipal principal = currentPrincipal();
        return mfaService.initiateSetup(principal.id(), principal.getUsername());
    }

    @PostMapping("/enable")
    public ProfileResponse enable(@Valid @RequestBody EnableMfaRequest request) {
        UserPrincipal principal = currentPrincipal();
        boolean verified = mfaService.verifyCode(principal.id(), request.code());
        if (!verified) {
            throw new UnauthorizedException("Invalid MFA code");
        }
        var user = userService.findById(principal.id());
        return UserMapper.toProfileResponse(user);
    }

    @DeleteMapping
    public ProfileResponse disable() {
        UserPrincipal principal = currentPrincipal();
        mfaService.disableMfa(principal.id());
        var user = userService.findById(principal.id());
        return UserMapper.toProfileResponse(user);
    }

    private UserPrincipal currentPrincipal() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof UserPrincipal principal)) {
            throw new UnauthorizedException("Unauthenticated");
        }
        return principal;
    }
}
