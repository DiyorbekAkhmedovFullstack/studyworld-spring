package com.studyworld.profile.web;

import com.studyworld.profile.dto.PasswordChangeRequest;
import com.studyworld.profile.dto.ProfilePictureUpdateRequest;
import com.studyworld.profile.dto.ProfileResponse;
import com.studyworld.profile.dto.ProfileUpdateRequest;
import com.studyworld.profile.service.ProfileService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @GetMapping
    public ProfileResponse me() {
        return profileService.getCurrentProfile();
    }

    @PutMapping
    public ProfileResponse updateProfile(@Valid @RequestBody ProfileUpdateRequest request) {
        return profileService.updateProfile(request);
    }

    @PutMapping("/password")
    public ResponseEntity<Void> updatePassword(@Valid @RequestBody PasswordChangeRequest request) {
        profileService.updatePassword(request);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/picture")
    public ProfileResponse updatePicture(@Valid @RequestBody ProfilePictureUpdateRequest request) {
        return profileService.updateProfilePicture(request);
    }
}
