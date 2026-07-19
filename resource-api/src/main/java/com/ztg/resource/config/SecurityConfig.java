package com.ztg.resource.config;

import com.ztg.resource.filter.GatewayTrustFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import com.ztg.common.web.RequestIdFilter;

/**
 * Resource Server 보안 설정 — Keycloak JWT(Bearer) 검증. 서명/만료/issuer는 issuer-uri로
 * 자동 구성되는 JwtDecoder가 담당한다. 세션 없는 STATELESS + CSRF off,
 * 명시적으로 열지 않은 모든 경로는 401(fail-close).
 */
@Configuration
public class SecurityConfig {

    /**
     * @param trustSecret 게이트웨이 신뢰 헤더의 공유 비밀. 코드 기본값을 두지 않는다 —
     *                    설정 누락 시 노출된 기본 비밀로 조용히 뜨는 대신 기동 실패(fail-fast).
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            @Value("${ztg.resource.trust-secret}") String trustSecret)
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Prometheus 스크랩용으로 토큰 없이 허용(데모; 운영은 망분리/별도 인증).
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("admin")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                // 토큰 인증보다 먼저 신뢰 헤더를 확인해 게이트웨이 우회 직접호출을 차단.
                .addFilterBefore(new GatewayTrustFilter(trustSecret), BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    /** 보안 필터체인보다 먼저 등록(HIGHEST_PRECEDENCE) — 401/403 거부 로그까지 같은 요청 ID로 상관되게. */
    @Bean
    FilterRegistrationBean<RequestIdFilter> requestIdFilter() {
        FilterRegistrationBean<RequestIdFilter> reg = new FilterRegistrationBean<>(new RequestIdFilter());
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }
}
