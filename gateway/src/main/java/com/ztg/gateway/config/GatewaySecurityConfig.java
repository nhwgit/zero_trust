package com.ztg.gateway;

import java.time.Clock;

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

    /**
     * issuer의 JWKS로 서명을, issuer-uri로 iss/exp를 검증하는 디코더. 커스텀 필터가 사용한다.
     *
     * <p><b>jwk-set-uri 분리(컨테이너화):</b> 기본은 {@code fromIssuerLocation}으로 issuer-uri의
     * .well-known에서 JWKS를 자동 조회한다. 그러나 컨테이너 안에선 토큰의 {@code iss}(예:
     * {@code localhost:8081})와 게이트웨이가 실제로 닿을 수 있는 Keycloak 주소({@code keycloak:8080})가
     * 다르다. 이때 {@code ztg.gateway.jwk-set-uri}를 주면 <b>키는 그 URL에서 받고 iss 검증은 issuer-uri로</b>
     * 유지한다 → 토큰 iss를 바꾸지 않아 기존(호스트 bootRun) 경로와 호환된다.
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

    /**
     * 자동 보안체인을 무력화한다. 게이트웨이의 인증/인가는 {@link JwtAuthGlobalFilter}가 맡으므로
     * 여기서는 모든 교환을 허용하고(httpBasic/formLogin 제거), CSRF도 끈다(순수 토큰 트래픽).
     */
    /**
     * 요청 시각(hour-of-day) 위험 신호를 산출하는 시계. 빈으로 분리해 테스트에서 고정 시계로
     * 대체할 수 있게 한다(업무시간 외 신호의 결정적 검증). 기본은 시스템 기본 타임존.
     */
    @Bean
    Clock clock() {
        return Clock.systemDefaultZone();
    }

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
