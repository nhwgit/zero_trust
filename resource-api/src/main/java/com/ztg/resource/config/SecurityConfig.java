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
 * Resource Server 보안 설정.
 *
 * <p>Keycloak이 발급한 JWT(Bearer)를 검증한다. 서명/만료/issuer 검증은
 * issuer-uri로 자동 구성되는 JwtDecoder가 담당한다(JWKS 공개키로 검증).
 *
 * <p>설계 메모:
 * <ul>
 *   <li><b>STATELESS</b>: 세션을 만들지 않는다. 매 요청을 토큰만으로 인증 — 제로트러스트 기본값.</li>
 *   <li><b>CSRF off</b>: 쿠키 세션이 없는 순수 토큰 API라 CSRF 보호가 불필요.</li>
 *   <li><b>fail-close</b>: anyRequest().authenticated() — 명시적으로 열지 않은 모든 경로는 401.</li>
 * </ul>
 */
@Configuration
public class SecurityConfig {

    /** 게이트웨이가 주입하는 내부 신뢰 헤더의 공유 비밀(기본값은 dev용, gateway와 동일). */
    @Value("${ztg.resource.trust-secret:ztg-gateway-trust-secret}")
    private String trustSecret;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 관측 엔드포인트: Prometheus 스크랩용으로 토큰 없이 허용(데모; 운영은 망분리/별도 인증).
                        .requestMatchers("/actuator/**").permitAll()
                        // 관리자 전용: admin 역할이 없으면 403
                        .requestMatchers("/api/admin/**").hasRole("admin")
                        // 그 외 모든 요청: 유효한 토큰 필요(없으면 401)
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                // PEP(게이트웨이) 경유 강제: 토큰 인증보다 먼저 신뢰 헤더를 확인해 우회 직접호출을 차단.
                .addFilterBefore(new GatewayTrustFilter(trustSecret), BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    /**
     * 요청 추적 ID 필터를 보안 필터체인보다 먼저 등록한다(HIGHEST_PRECEDENCE).
     * 게이트웨이가 전파한 {@code X-Request-Id}를 MDC에 실어, 토큰 거부(401)나 신뢰헤더
     * 거부(403) 로그까지 같은 ID로 상관되게 한다(분산 추적).
     */
    @Bean
    FilterRegistrationBean<RequestIdFilter> requestIdFilter() {
        FilterRegistrationBean<RequestIdFilter> reg = new FilterRegistrationBean<>(new RequestIdFilter());
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }

    /** realm_access.roles → ROLE_* 권한으로 매핑하는 변환기를 토큰 인증에 연결한다. */
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }
}
