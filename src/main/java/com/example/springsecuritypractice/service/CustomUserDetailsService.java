package com.example.springsecuritypractice.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!username.equals("user1")) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
        }

        return User.builder()
                .username("user1")
                .password("{noop}1234")
                .roles("USER")
                .build();
    }
}
