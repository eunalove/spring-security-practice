package com.example.springsecuritypractice.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return switch (username) {
            case "user1" -> User.builder()
                    .username("user1")
                    .password(passwordEncoder.encode("1234"))
                    .roles("USER")
                    .build();
            case "admin" -> User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("1234"))
                    .roles("ADMIN")
                    .build();
            default -> throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
        };
    }
}