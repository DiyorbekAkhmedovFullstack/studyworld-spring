package com.studyworld.profile.service;

import com.studyworld.profile.dto.PasswordChangeRequest;
import com.studyworld.profile.dto.ProfilePictureUpdateRequest;
import com.studyworld.profile.dto.ProfileResponse;
import com.studyworld.profile.dto.ProfileUpdateRequest;

public interface ProfileService {

    ProfileResponse getCurrentProfile();

    ProfileResponse updateProfile(ProfileUpdateRequest request);

    void updatePassword(PasswordChangeRequest request);

    ProfileResponse updateProfilePicture(ProfilePictureUpdateRequest request);
}
