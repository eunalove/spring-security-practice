package com.example.springsecuritypractice.config;

import com.example.springsecuritypractice.jwt.JwtAuthenticationFilter;
import com.example.springsecuritypractice.jwt.JwtSuccessHandler;
import com.example.springsecuritypractice.jwt.JwtUtil;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:8080"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                    UserDetailsService userDetailsService) throws Exception {

        http
                .cors(Customizer.withDefaults())
//                .csrf(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                // ✅ JWT는 Stateless → 서버에 세션을 저장하지 않음
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // [세션 로그인 설정 - JWT 방식에서 비활성화]
                // .sessionManagement(session -> session
                //         .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                //         .sessionFixation(sessionFixation -> sessionFixation.migrateSession())
                //         .maximumSessions(1)
                //         .maxSessionsPreventsLogin(false)
                // )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")  // ✅ ADMIN만 접근 가능
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        // ✅ 로그인 성공 시 JWT를 쿠키에 담아주는 핸들러 등록
                        .successHandler(new JwtSuccessHandler(jwtUtil))
                        // [세션 로그인 설정 - JWT 방식에서 비활성화]
                        // .defaultSuccessUrl("/mypage", true)
                )
                // [세션 로그인 설정 - JWT 방식에서 비활성화]
                // .logout(logout -> logout
                //         .logoutSuccessUrl("/login")
                //         .permitAll()
                // )
                // ✅ 쿠키의 JWT를 검증해서 SecurityContext에 인증 정보를 세팅하는 필터
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}