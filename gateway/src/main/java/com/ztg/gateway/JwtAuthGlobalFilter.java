package com.ztg.gateway;

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
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * PEP의 핵심 — 모든 라우팅 요청을 가로채 JWT를 검증한다.
 *
 * <p>흐름:
 * <ol>
 *   <li>{@code Authorization: Bearer ...}가 없으면 → 401 (백엔드로 전달 안 함).</li>
 *   <li>토큰이 있으면 {@link org.springframework.security.oauth2.jwt.ReactiveJwtDecoder}로
 *       서명/iss/exp를 검증. 실패 시 → 401.</li>
 *   <li>검증 통과 시에만 내부 신뢰 헤더를 실어 {@code resource-api}로 전달한다.</li>
 * </ol>
 *
 * <p>설계 메모(fail-close): 토큰이 없거나 검증에 실패하거나 디코더 호출 자체가 에러를 던지면
 * <b>무조건 차단(401)</b>한다. "판단 불가 = 차단"이 제로트러스트의 안전 기본값이며, 의심스러운
 * 트래픽이 백엔드로 새어 나가지 않게 한다.
 */
@Component
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. resource-api가 동일 값을 검증한다. */
    static final String TRUST_HEADER = "X-Gateway-Auth";
    private static final String BEARER_PREFIX = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGlobalFilter.class);

    private final org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder;
    private final String trustSecret;

    JwtAuthGlobalFilter(org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder,
                        @Value("${ztg.gateway.trust-secret}") String trustSecret) {
        this.jwtDecoder = jwtDecoder;
        this.trustSecret = trustSecret;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authz = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authz == null || !authz.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return reject(exchange, "missing or malformed Authorization header");
        }
        String token = authz.substring(BEARER_PREFIX.length()).trim();
        return jwtDecoder.decode(token)
                .flatMap(jwt -> chain.filter(exchange.mutate().request(withTrustHeader(exchange)).build()))
                // 검증 실패(JwtException 계열)만 401로 차단한다. 백엔드 포워딩 단계의 에러까지
                // 여기서 삼키면 모든 장애가 401로 둔갑하므로, catch 범위를 JwtException으로 좁힌다.
                .onErrorResume(JwtException.class,
                        e -> reject(exchange, "JWT validation failed: " + e.getMessage()));
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

    /** fail-close: 401로 즉시 응답하고 체인을 끊는다(백엔드 미전달). */
    private Mono<Void> reject(ServerWebExchange exchange, String reason) {
        log.debug("PEP reject: {} ({} {})", reason,
                exchange.getRequest().getMethod(), exchange.getRequest().getPath());
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    /** 라우팅(백엔드 전달) 전에 실행되도록 낮은 order. */
    @Override
    public int getOrder() {
        return -1;
    }
}
