package com.ztg.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * PEP 핵심 필터의 단위 검증. ReactiveJwtDecoder는 mock으로 대체한다(실제 JWKS 미접속).
 *
 * <p>검증 포인트:
 * <ul>
 *   <li>토큰 없음 → 401, 백엔드(chain) 미호출 (fail-close).</li>
 *   <li>토큰 유효 → chain 호출 + 신뢰 헤더가 비밀 값으로 주입됨.</li>
 *   <li>토큰 무효 → 401, 백엔드 미호출 (fail-close).</li>
 *   <li>클라이언트가 위조한 신뢰 헤더는 게이트웨이 값으로 덮어써짐.</li>
 * </ul>
 */
class JwtAuthGlobalFilterTest {

    private static final String SECRET = "test-trust-secret";

    private final ReactiveJwtDecoder decoder = mock(ReactiveJwtDecoder.class);
    private final JwtAuthGlobalFilter filter = new JwtAuthGlobalFilter(decoder, SECRET);

    @Test
    void missing_token_is_401_and_does_not_forward() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello"));
        AtomicReference<Boolean> forwarded = new AtomicReference<>(false);
        GatewayFilterChain chain = e -> {
            forwarded.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void valid_token_forwards_with_trust_header() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = e -> {
            forwarded.set(e);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isNotNull();
        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(JwtAuthGlobalFilter.TRUST_HEADER)).isEqualTo(SECRET);
    }

    @Test
    void invalid_token_is_401_and_does_not_forward() {
        when(decoder.decode("bad-token")).thenReturn(Mono.error(new JwtException("expired")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bad-token"));
        AtomicReference<Boolean> forwarded = new AtomicReference<>(false);
        GatewayFilterChain chain = e -> {
            forwarded.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void client_supplied_trust_header_is_overwritten() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                        .header(JwtAuthGlobalFilter.TRUST_HEADER, "forged-by-client"));
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = e -> {
            forwarded.set(e);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(JwtAuthGlobalFilter.TRUST_HEADER)).isEqualTo(SECRET);
    }

    private static Jwt sampleJwt() {
        return Jwt.withTokenValue("good-token")
                .header("alg", "RS256")
                .subject("alice")
                .claim("preferred_username", "alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }
}
