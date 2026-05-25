package com.ztg.gateway;

import java.util.Map;

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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;

import reactor.core.publisher.Mono;

/**
 * PEP의 핵심 — 모든 라우팅 요청을 가로채 (1) JWT를 검증하고 (2) PDP에 인가를 질의한다.
 *
 * <p>흐름:
 * <ol>
 *   <li>{@code Authorization: Bearer ...}가 없으면 → 401 (백엔드로 전달 안 함).</li>
 *   <li>토큰이 있으면 {@link org.springframework.security.oauth2.jwt.ReactiveJwtDecoder}로
 *       서명/iss/exp를 검증. 실패 시 → 401.</li>
 *   <li>검증 통과 시 PDP에 "이 주체가 이 리소스에 접근 가능?"을 질의한다.
 *       DENY면 → 403 + 사유 헤더(백엔드로 전달 안 함).</li>
 *   <li>ALLOW일 때만 내부 신뢰 헤더를 실어 {@code resource-api}로 전달한다.</li>
 * </ol>
 *
 * <p>설계 메모(fail-close): 토큰이 없거나 검증 실패면 401, PDP가 DENY거나 <b>PDP 호출 자체가
 * 실패</b>(다운/타임아웃)하면 403으로 차단한다. "인증 불가 = 401, 인가 불가 = 403"으로
 * 의심스러운 트래픽이 백엔드로 새어 나가지 않게 한다.
 */
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. resource-api가 동일 값을 검증한다. */
    static final String TRUST_HEADER = "X-Gateway-Auth";
    /** PDP가 DENY한 사유를 클라이언트에게 노출하는 헤더(감사/디버깅용). */
    static final String DENY_REASON_HEADER = "X-Denied-Reason";
    private static final String BEARER_PREFIX = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGlobalFilter.class);

    private final org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder;
    private final PdpClient pdpClient;
    private final String trustSecret;

    JwtAuthGlobalFilter(org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder,
                        PdpClient pdpClient,
                        @Value("${ztg.gateway.trust-secret}") String trustSecret) {
        this.jwtDecoder = jwtDecoder;
        this.pdpClient = pdpClient;
        this.trustSecret = trustSecret;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authz = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authz == null || !authz.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return reject401(exchange, "missing or malformed Authorization header");
        }
        String token = authz.substring(BEARER_PREFIX.length()).trim();
        return jwtDecoder.decode(token)
                // 인증 통과 → 인가 질의(PDP). 검증 실패(JwtException 계열)만 401로 좁혀 잡는다.
                .flatMap(jwt -> authorizeThenForward(exchange, chain, jwt))
                .onErrorResume(JwtException.class,
                        e -> reject401(exchange, "JWT validation failed: " + e.getMessage()));
    }

    /** PDP에 인가를 질의하고 ALLOW면 백엔드로 전달, DENY/오류면 403으로 차단한다. */
    private Mono<Void> authorizeThenForward(ServerWebExchange exchange, GatewayFilterChain chain, Jwt jwt) {
        DecisionRequest request = new DecisionRequest(
                subjectOf(jwt),
                exchange.getRequest().getMethod().name(),
                exchange.getRequest().getPath().value(),
                Map.of());
        return pdpClient.decide(request)
                // fail-close: PDP 호출 실패는 "판단 불가"이므로 DENY로 환산해 403 처리한다.
                .onErrorResume(e -> Mono.just(
                        DecisionResponse.deny("PDP unavailable: " + e.getMessage())))
                .flatMap(decision -> {
                    if (decision.isAllowed()) {
                        return chain.filter(exchange.mutate().request(withTrustHeader(exchange)).build());
                    }
                    return reject403(exchange, decision.reason());
                });
    }

    /** 인가 주체 식별자: preferred_username 우선, 없으면 sub. PIP 조회 키로 쓰인다. */
    private static String subjectOf(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        return username != null ? username : jwt.getSubject();
    }

    /**
     * 신뢰 헤더를 실은 요청을 만든다.
     *
     * <p>들어온 요청 헤더는 read-only({@code ReadOnlyHttpHeaders})라 빌더로 직접 set 하면
     * {@link UnsupportedOperationException}이 난다. 그래서 쓰기 가능한 복사본을 만들어
     * 신뢰 헤더를 덮어쓰고(클라이언트 위조분 제거), 디코레이터로 그 헤더를 노출한다.
     */
    private ServerHttpRequest withTrustHeader(ServerWebExchange exchange) {
        HttpHeaders writable = new HttpHeaders();
        writable.addAll(exchange.getRequest().getHeaders());
        writable.set(TRUST_HEADER, trustSecret);
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                return writable;
            }
        };
    }

    /** fail-close(인증): 401로 즉시 응답하고 체인을 끊는다(백엔드 미전달). */
    private Mono<Void> reject401(ServerWebExchange exchange, String reason) {
        log.debug("PEP reject 401: {} ({} {})", reason,
                exchange.getRequest().getMethod(), exchange.getRequest().getPath());
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    /** fail-close(인가): 403으로 즉시 응답하고 사유를 헤더로 노출한다(백엔드 미전달). */
    private Mono<Void> reject403(ServerWebExchange exchange, String reason) {
        log.debug("PEP reject 403: {} ({} {})", reason,
                exchange.getRequest().getMethod(), exchange.getRequest().getPath());
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        if (reason != null) {
            // 헤더는 단일 라인 ASCII만 허용 — 개행/CR을 공백으로 치환해 헤더 분리(injection)를 막는다.
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
