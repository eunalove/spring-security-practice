package com.example.springsecuritypractice.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String username = authentication.getName();
        // 인증 객체에서 첫 번째 권한(role)을 꺼내 토큰에 담음
        String role = authentication.getAuthorities().iterator().next().getAuthority();
        String token = jwtUtil.generateToken(username, role);

        // HttpOnly + SameSite=Lax 조합으로 XSS, CSRF 방어
        // Jakarta Cookie API는 SameSite를 지원하지 않아 헤더에 직접 설정
        response.setHeader("Set-Cookie",
                "jwt=" + token + "; Path=/; HttpOnly; Max-Age=3600; SameSite=Lax");

        // role에 따라 리다이렉트 경로 분기
        if ("ROLE_ADMIN".equals(role)) {
            response.sendRedirect("/admin");
        } else {
            response.sendRedirect("/mypage");
        }
    }
}