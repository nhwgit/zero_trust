package com.ztg.gateway.filter;

import com.ztg.gateway.client.PdpClient;
import com.ztg.gateway.risk.SubjectRateObserver;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * PEP 핵심 필터의 단위 검증. ReactiveJwtDecoder와 PdpClient는 mock으로 대체한다.
 *
 * <p>검증 포인트:
 * <ul>
 *   <li>토큰 없음 → 401, 백엔드(chain) 미호출 (fail-close).</li>
 *   <li>토큰 무효 → 401, 백엔드 미호출 (fail-close).</li>
 *   <li>토큰 유효 + PDP ALLOW → chain 호출 + 신뢰 헤더가 비밀 값으로 주입됨.</li>
 *   <li>클라이언트가 위조한 신뢰 헤더는 게이트웨이 값으로 덮어써짐.</li>
 *   <li>토큰 유효 + PDP DENY → 403 + 사유 헤더, 백엔드 미호출.</li>
 *   <li>토큰 유효 + PDP 호출 실패 → 403 (fail-close), 백엔드 미호출.</li>
 *   <li>인가 결정이 ztg.authz.decisions 카운터에 decision/cause 태그로 집계됨(관측).</li>
 * </ul>
 */
class JwtAuthGlobalFilterTest {

    private static final String SECRET = "test-trust-secret";

    private final ReactiveJwtDecoder decoder = mock(ReactiveJwtDecoder.class);
    private final PdpClient pdpClient = mock(PdpClient.class);
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final SubjectRateObserver rateObserver = new SubjectRateObserver(Duration.ofSeconds(10));
    // 09시(UTC)로 고정 — hour-of-day 신호를 결정적으로 검증한다.
    private final Clock clock = Clock.fixed(Instant.parse("2026-06-01T09:00:00Z"), ZoneId.of("UTC"));
    private final JwtAuthGlobalFilter filter =
            new JwtAuthGlobalFilter(decoder, pdpClient, SECRET, registry, rateObserver, clock);

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
    void valid_token_allowed_by_pdp_forwards_with_trust_header() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));
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
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));
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

    @Test
    void pdp_deny_is_403_with_reason_and_does_not_forward() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.just(DecisionResponse.deny("payroll denied: department must be finance")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/payroll")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));
        AtomicReference<Boolean> forwarded = new AtomicReference<>(false);
        GatewayFilterChain chain = e -> {
            forwarded.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders()
                .getFirst(JwtAuthGlobalFilter.DENY_REASON_HEADER)).contains("finance");
    }

    @Test
    void pdp_call_failure_fails_closed_to_403() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.error(new RuntimeException("connection refused")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/payroll")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));
        AtomicReference<Boolean> forwarded = new AtomicReference<>(false);
        GatewayFilterChain chain = e -> {
            forwarded.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void allow_increments_allow_decision_counter() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        assertThat(registry.counter("ztg.authz.decisions", "decision", "allow", "cause", "none").count())
                .isEqualTo(1.0);
        assertThat(registry.timer("ztg.pdp.requests", "outcome", "success").count()).isEqualTo(1L);
    }

    @Test
    void policy_deny_increments_deny_policy_counter() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.just(DecisionResponse.deny("department must be finance")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/payroll")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        assertThat(registry.counter("ztg.authz.decisions", "decision", "deny", "cause", "policy").count())
                .isEqualTo(1.0);
    }

    @Test
    void pdp_failure_increments_deny_pdp_error_counter_and_error_timer() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        when(pdpClient.decide(any(DecisionRequest.class), anyString()))
                .thenReturn(Mono.error(new RuntimeException("connection refused")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/payroll")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        // fail-close가 "정책 거부"가 아니라 "장애로 인한 거부"로 분류되는지 — 가용성 신호.
        assertThat(registry.counter("ztg.authz.decisions", "decision", "deny", "cause", "pdp_error").count())
                .isEqualTo(1.0);
        assertThat(registry.timer("ztg.pdp.requests", "outcome", "error").count()).isEqualTo(1L);
    }

    @Test
    void generates_request_id_and_echoes_it_on_response() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello"));  // 토큰 없음 → 401이어도 요청ID는 부여된다

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        assertThat(exchange.getResponse().getHeaders().getFirst(JwtAuthGlobalFilter.REQUEST_ID_HEADER))
                .isNotBlank();
    }

    @Test
    void incoming_request_id_is_propagated_to_pdp_and_backend() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        ArgumentCaptor<String> pdpRequestId = ArgumentCaptor.forClass(String.class);
        when(pdpClient.decide(any(DecisionRequest.class), pdpRequestId.capture()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                        .header(JwtAuthGlobalFilter.REQUEST_ID_HEADER, "trace-xyz"));
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, e -> {
            forwarded.set(e);
            return Mono.empty();
        })).verifyComplete();

        // 같은 추적 ID가 (1) PDP 질의와 (2) 백엔드 전달 요청 헤더로 그대로 흐른다(분산 추적).
        assertThat(pdpRequestId.getValue()).isEqualTo("trace-xyz");
        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(JwtAuthGlobalFilter.REQUEST_ID_HEADER)).isEqualTo("trace-xyz");
        assertThat(exchange.getResponse().getHeaders()
                .getFirst(JwtAuthGlobalFilter.REQUEST_ID_HEADER)).isEqualTo("trace-xyz");
    }

    @Test
    void observed_risk_signals_are_carried_in_decision_context() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        ArgumentCaptor<DecisionRequest> sent = ArgumentCaptor.forClass(DecisionRequest.class);
        when(pdpClient.decide(sent.capture(), anyString()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                        .header(JwtAuthGlobalFilter.FORWARDED_FOR_HEADER, "203.0.113.7, 10.0.0.1"));

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        // 게이트웨이가 관측한 IP(XFF 첫 홉)·레이트·시각이 PDP 질의 context에 RiskSignals 키로 실린다.
        java.util.Map<String, String> ctx = sent.getValue().context();
        assertThat(ctx.get(com.ztg.common.model.RiskSignals.CTX_SOURCE_IP)).isEqualTo("203.0.113.7");
        assertThat(ctx.get(com.ztg.common.model.RiskSignals.CTX_REQUESTS_IN_WINDOW)).isEqualTo("1");
        assertThat(ctx.get(com.ztg.common.model.RiskSignals.CTX_HOUR_OF_DAY)).isEqualTo("9");
    }

    @Test
    void requests_in_window_increases_across_repeated_calls_by_same_subject() {
        when(decoder.decode("good-token")).thenReturn(Mono.just(sampleJwt()));
        ArgumentCaptor<DecisionRequest> sent = ArgumentCaptor.forClass(DecisionRequest.class);
        when(pdpClient.decide(sent.capture(), anyString()))
                .thenReturn(Mono.just(DecisionResponse.allow("ok")));

        for (int i = 0; i < 3; i++) {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get("/api/hello")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));
            StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();
        }

        // 같은 주체(alice)가 윈도우 안에서 거듭 호출하면 레이트가 1→2→3으로 누적된다.
        assertThat(sent.getAllValues()).extracting(
                        r -> r.context().get(com.ztg.common.model.RiskSignals.CTX_REQUESTS_IN_WINDOW))
                .containsExactly("1", "2", "3");
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
