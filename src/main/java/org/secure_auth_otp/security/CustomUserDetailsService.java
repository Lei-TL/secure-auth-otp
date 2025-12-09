package org.secure_auth_otp.security;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.entity.User;
import org.secure_auth_otp.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        boolean accountLocked = user.getLockoutUntil() != null
                && user.getLockoutUntil().isAfter(LocalDateTime.now());

        return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
                .password(user.getPasswordHash())
                .authorities("ROLE_USER")
                .accountLocked(accountLocked)
                .disabled(!user.isActive())
                .build();
    }
}

