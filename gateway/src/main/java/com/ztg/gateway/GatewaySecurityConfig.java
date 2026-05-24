package com.ztg.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * 게이트웨이 보안 구성.
 *
 * <p>설계 메모: 토큰 검증(enforce)은 Spring Security의 자동 리소스서버 체인이 아니라
 * 커스텀 {@link JwtAuthGlobalFilter}가 단독으로 수행한다(PEP를 한 곳에 모으기 위함).
 * 그래서 Security 자동설정의 기본 체인은 <b>permitAll</b>로 비활성화해 길을 비켜준다.
 * 단, JWKS 기반 서명/iss/exp 검증을 손수 짜지 않으려고 {@link ReactiveJwtDecoder}만 빌려 쓴다.
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    /** issuer의 .well-known/JWKS로 서명·iss·exp를 검증하는 디코더. 커스텀 필터가 사용한다. */
    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${ztg.gateway.issuer-uri}") String issuerUri) {
        return ReactiveJwtDecoders.fromIssuerLocation(issuerUri);
    }

    /**
     * 자동 보안체인을 무력화한다. 게이트웨이의 인증/인가는 {@link JwtAuthGlobalFilter}가 맡으므로
     * 여기서는 모든 교환을 허용하고(httpBasic/formLogin 제거), CSRF도 끈다(순수 토큰 트래픽).
     */
    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(ex -> ex.anyExchange().permitAll())
                .build();
    }
}
