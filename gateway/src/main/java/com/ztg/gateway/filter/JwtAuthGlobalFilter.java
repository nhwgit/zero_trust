package com.ztg.gateway.filter;

import com.ztg.gateway.client.PdpClient;
import com.ztg.gateway.risk.RiskContextObserver;
import java.util.UUID;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.web.GatewayTrust;
import com.ztg.common.web.RequestId;

import reactor.core.publisher.Mono;

/**
 * PEP 핵심 필터 — 모든 라우팅 요청을 가로채 JWT를 검증하고 PDP에 인가를 질의한다.
 * fail-close: 인증 불가 401, 인가 불가(정책 DENY·PDP 호출 실패) 403 — 의심 트래픽은 백엔드에 닿지 않는다.
 * 위험 신호 관측(IP 두 축·레이트·시각)은 {@link RiskContextObserver}가 담당한다.
 */
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. resource-api가 동일 값을 검증한다. */
    public static final String TRUST_HEADER = GatewayTrust.HEADER;
    /** PDP DENY 사유를 노출하는 헤더(감사/디버깅용). */
    public static final String DENY_REASON_HEADER = "X-Denied-Reason";
    static final String REQUEST_ID_HEADER = RequestId.HEADER;
    private static final String BEARER_PREFIX = "Bearer ";
    /** fail-close DENY 사유의 접두어 — 거부 원인(cause) 분류에 쓴다. */
    static final String PDP_UNAVAILABLE_PREFIX = "PDP unavailable: ";
    private static final String REQUEST_ID_ATTR = JwtAuthGlobalFilter.class.getName() + ".requestId";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGlobalFilter.class);

    private final ReactiveJwtDecoder jwtDecoder;
    private final PdpClient pdpClient;
    private final String trustSecret;
    private final MeterRegistry meterRegistry;
    private final RiskContextObserver riskContextObserver;

    JwtAuthGlobalFilter(ReactiveJwtDecoder jwtDecoder,
                        PdpClient pdpClient,
                        @Value("${ztg.gateway.trust-secret}") String trustSecret,
                        MeterRegistry meterRegistry,
                        RiskContextObserver riskContextObserver) {
        this.jwtDecoder = jwtDecoder;
        this.pdpClient = pdpClient;
        this.trustSecret = trustSecret;
        this.meterRegistry = meterRegistry;
        this.riskContextObserver = riskContextObserver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 요청 추적 ID를 제일 먼저 확정해 모든 로그/응답이 같은 ID로 묶이게 한다.
        String requestId = resolveRequestId(exchange);
        exchange.getAttributes().put(REQUEST_ID_ATTR, requestId);
        exchange.getResponse().getHeaders().set(REQUEST_ID_HEADER, requestId);

        String authz = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authz == null || !authz.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return reject401(exchange, "missing or malformed Authorization header");
        }
        String token = authz.substring(BEARER_PREFIX.length()).trim();
        return jwtDecoder.decode(token)
                .flatMap(jwt -> authorizeThenForward(exchange, chain, jwt))
                .onErrorResume(JwtException.class,
                        e -> reject401(exchange, "JWT validation failed: " + e.getMessage()));
    }

    /** PDP에 인가를 질의하고 ALLOW면 백엔드로 전달, DENY/오류면 403으로 차단한다. */
    private Mono<Void> authorizeThenForward(ServerWebExchange exchange, GatewayFilterChain chain, Jwt jwt) {
        String subject = subjectOf(jwt);
        String method = exchange.getRequest().getMethod().name();
        String path = exchange.getRequest().getPath().value();
        String requestId = requestIdOf(exchange);
        return riskContextObserver.observe(exchange, subject)
                .map(context -> new DecisionRequest(subject, method, path, context))
                .flatMap(request -> decide(request, requestId))
                .flatMap(decision -> {
                    if (decision.isAllowed()) {
                        meterRegistry.counter("ztg.authz.decisions", "decision", "allow", "cause", "none").increment();
                        log.info("authz decision=ALLOW subject={} method={} path={} requestId={}",
                                subject, method, path, requestId);
                        return chain.filter(exchange.mutate().request(withTrustHeader(exchange)).build());
                    }
                    // PDP 호출 실패(fail-close)와 정책상 거부를 구분해 가용성/정책을 따로 본다.
                    String cause = decision.reason() != null
                            && decision.reason().startsWith(PDP_UNAVAILABLE_PREFIX) ? "pdp_error" : "policy";
                    meterRegistry.counter("ztg.authz.decisions", "decision", "deny", "cause", cause).increment();
                    log.info("authz decision=DENY cause={} subject={} method={} path={} reason=\"{}\" requestId={}",
                            cause, subject, method, path, decision.reason(), requestId);
                    return reject403(exchange, decision.reason());
                });
    }

    /** PDP 호출(지연 측정 포함). fail-close: 호출 실패는 "판단 불가"이므로 DENY로 환산한다. */
    private Mono<DecisionResponse> decide(DecisionRequest request, String requestId) {
        Timer.Sample sample = Timer.start(meterRegistry);
        return pdpClient.decide(request, requestId)
                .doOnNext(d -> sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "success")))
                .onErrorResume(e -> {
                    sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "error"));
                    return Mono.just(DecisionResponse.indeterminate(PDP_UNAVAILABLE_PREFIX + e.getMessage()));
                });
    }

    private static String resolveRequestId(ServerWebExchange exchange) {
        String incoming = exchange.getRequest().getHeaders().getFirst(REQUEST_ID_HEADER);
        return (incoming != null && !incoming.isBlank()) ? incoming : UUID.randomUUID().toString();
    }

    private static String requestIdOf(ServerWebExchange exchange) {
        Object id = exchange.getAttribute(REQUEST_ID_ATTR);
        return id != null ? id.toString() : "unknown";
    }

    /** 인가 주체 식별자: preferred_username 우선, 없으면 sub. PIP 조회 키로 쓰인다. */
    private static String subjectOf(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        return username != null ? username : jwt.getSubject();
    }

    /**
     * 신뢰 헤더를 실은 요청을 만든다. 들어온 요청 헤더는 read-only라 쓰기 가능한 복사본에
     * 신뢰 헤더를 덮어쓰고(클라이언트 위조분 제거) 디코레이터로 노출한다.
     */
    private ServerHttpRequest withTrustHeader(ServerWebExchange exchange) {
        HttpHeaders writable = new HttpHeaders();
        writable.addAll(exchange.getRequest().getHeaders());
        writable.set(TRUST_HEADER, trustSecret);
        writable.set(REQUEST_ID_HEADER, requestIdOf(exchange));
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                return writable;
            }
        };
    }

    private Mono<Void> reject401(ServerWebExchange exchange, String reason) {
        log.info("authn reject=401 reason=\"{}\" method={} path={} requestId={}", reason,
                exchange.getRequest().getMethod(), exchange.getRequest().getPath(), requestIdOf(exchange));
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> reject403(ServerWebExchange exchange, String reason) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        if (reason != null) {
            // 헤더는 단일 라인만 허용 — 개행/CR 치환으로 헤더 분리(injection)를 막는다.
            exchange.getResponse().getHeaders().set(DENY_REASON_HEADER, reason.replaceAll("[\\r\\n]", " "));
        }
        return exchange.getResponse().setComplete();
    }

    /** 라우팅(백엔드 전달) 전에 실행되도록 낮은 order. */
    @Override
    public int getOrder() {
        return -1;
    }
}
