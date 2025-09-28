package com.studyworld.auth.service;

import com.studyworld.user.model.User;
import com.studyworld.user.model.UserRole;
import java.time.Instant;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserPrincipal implements UserDetails {

    private final User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    public UUID id() {
        return user.id();
    }

    public boolean isEmailVerified() {
        return user.emailVerified();
    }

    public boolean isMfaEnabled() {
        return user.mfaEnabled();
    }

    public String mfaSecret() {
        return user.mfaSecret();
    }

    public User domainUser() {
        return user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<UserRole> roles = user.roles();
        if (roles == null || roles.isEmpty()) {
            return Set.of();
        }
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public String getPassword() {
        return user.passwordHash();
    }

    @Override
    public String getUsername() {
        return user.email();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isLocked(Instant.now());
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !user.isPasswordExpired(Instant.now());
    }

    @Override
    public boolean isEnabled() {
        return user.enabled();
    }
}
