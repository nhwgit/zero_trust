package com.ztg.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;

/**
 * 게이트웨이 보안 구성. 토큰 검증(enforce)은 커스텀 {@link com.ztg.gateway.filter.JwtAuthGlobalFilter}가
 * 단독 수행하므로 기본 보안체인은 permitAll로 비켜주고, 서명/iss/exp 검증용 {@link ReactiveJwtDecoder}만 빌려 쓴다.
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    /**
     * JWKS 서명 + issuer 검증 디코더. 컨테이너 안에선 토큰 iss와 실제로 닿는 Keycloak 주소가 다르므로,
     * {@code ztg.gateway.jwk-set-uri}가 있으면 키는 그 URL에서 받고 iss 검증은 issuer-uri로 유지한다.
     */
    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${ztg.gateway.issuer-uri}") String issuerUri,
                                  @Value("${ztg.gateway.jwk-set-uri:}") String jwkSetUri) {
        if (StringUtils.hasText(jwkSetUri)) {
            NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
            decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
            return decoder;
        }
        return ReactiveJwtDecoders.fromIssuerLocation(issuerUri);
    }

    /** 자동 보안체인 무력화 — 모든 교환 허용, CSRF off(순수 토큰 트래픽). */
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
