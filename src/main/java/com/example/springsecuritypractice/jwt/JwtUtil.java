package com.example.springsecuritypractice.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private static final String SECRET = "spring-security-practice-jwt-secret-key-256bit!!";
    private static final long EXPIRATION_MS = 1000L * 60 * 60; // 1시간

    private final SecretKey secretKey = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    /**
     * username과 role을 담아 JWT 토큰 생성
     */
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .subject(username)
                .claim("role", role)   // 클레임에 role 추가
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(secretKey)
                .compact();
    }

    /**
     * 토큰에서 사용자 이름 추출
     */
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * 토큰에서 role 추출
     */
    public String extractRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    /**
     * 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}