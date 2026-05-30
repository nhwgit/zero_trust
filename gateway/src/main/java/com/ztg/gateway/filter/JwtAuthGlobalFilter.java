package com.ztg.gateway.filter;

import com.ztg.gateway.client.PdpClient;
import com.ztg.gateway.risk.SubjectRateObserver;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.LocalTime;
import java.util.LinkedHashMap;
import java.util.Map;
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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.web.RequestId;

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
    public static final String TRUST_HEADER = "X-Gateway-Auth";
    /** PDP가 DENY한 사유를 클라이언트에게 노출하는 헤더(감사/디버깅용). */
    public static final String DENY_REASON_HEADER = "X-Denied-Reason";
    /** 요청 추적 ID 헤더 — 들어온 값이 있으면 잇고, 없으면 생성해 다운스트림으로 전파한다(공용 상수). */
    static final String REQUEST_ID_HEADER = RequestId.HEADER;
    private static final String BEARER_PREFIX = "Bearer ";
    /** PDP 호출 실패(fail-close)로 만든 DENY 사유의 접두어. 거부 원인(cause) 분류에 쓴다. */
    static final String PDP_UNAVAILABLE_PREFIX = "PDP unavailable: ";
    /** 클라이언트와 게이트웨이 사이 프록시가 실제 출발지를 남기는 표준 헤더(첫 홉이 원 클라이언트). */
    static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    /** 요청 ID를 교환 속성으로 실어 reject/forward 경로에서 공유하기 위한 키. */
    private static final String REQUEST_ID_ATTR = JwtAuthGlobalFilter.class.getName() + ".requestId";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthGlobalFilter.class);

    private final org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder;
    private final PdpClient pdpClient;
    private final String trustSecret;
    private final MeterRegistry meterRegistry;
    private final SubjectRateObserver rateObserver;
    private final Clock clock;

    JwtAuthGlobalFilter(org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder,
                        PdpClient pdpClient,
                        @Value("${ztg.gateway.trust-secret}") String trustSecret,
                        MeterRegistry meterRegistry,
                        SubjectRateObserver rateObserver,
                        Clock clock) {
        this.jwtDecoder = jwtDecoder;
        this.pdpClient = pdpClient;
        this.trustSecret = trustSecret;
        this.meterRegistry = meterRegistry;
        this.rateObserver = rateObserver;
        this.clock = clock;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 요청 추적 ID 확정 — 모든 로그/응답이 같은 ID로 묶이도록 제일 먼저 정한다.
        String requestId = resolveRequestId(exchange);
        exchange.getAttributes().put(REQUEST_ID_ATTR, requestId);
        exchange.getResponse().getHeaders().set(REQUEST_ID_HEADER, requestId);

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
        String subject = subjectOf(jwt);
        String method = exchange.getRequest().getMethod().name();
        String path = exchange.getRequest().getPath().value();
        String requestId = requestIdOf(exchange);
        // PEP가 본 요청 맥락(출발지 IP·레이트·시각)을 위험 신호로 실어 PDP→PIP까지 전달한다(README 결정 #3).
        DecisionRequest request = new DecisionRequest(subject, method, path, observeRiskContext(exchange, subject));

        // PDP 호출 지연을 측정한다(p99는 application.yml의 히스토그램 설정으로 산출).
        Timer.Sample sample = Timer.start(meterRegistry);
        // 요청ID를 헤더로 실어 PDP/PIP 로그까지 같은 ID로 묶는다(분산 추적).
        return pdpClient.decide(request, requestId)
                .doOnNext(d -> sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "success")))
                // fail-close: PDP 호출 실패는 "판단 불가"이므로 DENY로 환산해 403 처리한다.
                .onErrorResume(e -> {
                    sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "error"));
                    return Mono.just(DecisionResponse.deny(PDP_UNAVAILABLE_PREFIX + e.getMessage()));
                })
                .flatMap(decision -> {
                    if (decision.isAllowed()) {
                        meterRegistry.counter("ztg.authz.decisions", "decision", "allow", "cause", "none").increment();
                        log.info("authz decision=ALLOW subject={} method={} path={} requestId={}",
                                subject, method, path, requestId);
                        return chain.filter(exchange.mutate().request(withTrustHeader(exchange)).build());
                    }
                    // 거부 원인 분류: PDP 호출 실패(fail-close)와 정책상 거부를 구분해 가용성/정책을 따로 본다.
                    String cause = decision.reason() != null
                            && decision.reason().startsWith(PDP_UNAVAILABLE_PREFIX) ? "pdp_error" : "policy";
                    meterRegistry.counter("ztg.authz.decisions", "decision", "deny", "cause", cause).increment();
                    log.info("authz decision=DENY cause={} subject={} method={} path={} reason=\"{}\" requestId={}",
                            cause, subject, method, path, decision.reason(), requestId);
                    return reject403(exchange, decision.reason());
                });
    }

    /** 들어온 {@code X-Request-Id}를 잇거나, 없으면 새로 생성한다(분산 추적의 상관 키). */
    private static String resolveRequestId(ServerWebExchange exchange) {
        String incoming = exchange.getRequest().getHeaders().getFirst(REQUEST_ID_HEADER);
        return (incoming != null && !incoming.isBlank()) ? incoming : UUID.randomUUID().toString();
    }

    /** filter() 진입 때 교환 속성에 실어둔 요청 ID를 꺼낸다. */
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
     * 이번 요청의 위험 신호를 관측해 {@link DecisionRequest#context()}에 실을 맵으로 만든다.
     *
     * <ul>
     *   <li><b>source-ip</b>: 출발지 IP. 프록시가 있으면 {@code X-Forwarded-For} 첫 홉, 없으면 소켓 원격주소.
     *       PIP가 직전 관측과 비교해 IP 변화를 가중하고, 캐시 키에도 반영돼 <b>새 IP는 자동 미스</b>가 된다.</li>
     *   <li><b>requests-in-window</b>: 이 주체의 슬라이딩 윈도우 요청 수(레이트 급증 신호). 매 요청 달라지는
     *       휘발성 값이라 캐시 키에선 제외한다({@link com.ztg.gateway.cache.DecisionCache} 결정 #3) — 급증은 epoch 무효화(step 4)로 처리.</li>
     *   <li><b>hour-of-day</b>: 요청 시각의 시(업무시간 외 신호). 주입 시계로 산출해 테스트에서 고정 가능.</li>
     * </ul>
     *
     * 신호 부재(IP 미상 등)는 키를 비워 두고, PDP/PIP 쪽에서 중립값으로 폴백한다(부재는 가중 아님).
     */
    private Map<String, String> observeRiskContext(ServerWebExchange exchange, String subject) {
        Map<String, String> context = new LinkedHashMap<>();
        String sourceIp = clientIp(exchange.getRequest());
        if (sourceIp != null) {
            context.put(RiskSignals.CTX_SOURCE_IP, sourceIp);
        }
        // 게이트웨이는 캐시 히트 포함 모든 요청을 보므로 여기서 레이트를 센다(권위 관측자).
        int requestsInWindow = rateObserver.record(subject);
        context.put(RiskSignals.CTX_REQUESTS_IN_WINDOW, Integer.toString(requestsInWindow));
        context.put(RiskSignals.CTX_HOUR_OF_DAY, Integer.toString(LocalTime.now(clock).getHour()));
        return context;
    }

    /**
     * 출발지 IP를 고른다: {@code X-Forwarded-For}가 있으면 첫(가장 왼쪽) 항목 = 원 클라이언트,
     * 없으면 TCP 소켓의 원격주소. 둘 다 없으면 {@code null}(신호 부재).
     */
    private static String clientIp(ServerHttpRequest request) {
        String forwarded = request.getHeaders().getFirst(FORWARDED_FOR_HEADER);
        if (forwarded != null && !forwarded.isBlank()) {
            // "client, proxy1, proxy2" → 첫 홉만. 프록시가 덧붙이므로 가장 왼쪽이 원 클라이언트다.
            return forwarded.split(",", 2)[0].trim();
        }
        InetSocketAddress remote = request.getRemoteAddress();
        if (remote != null && remote.getAddress() != null) {
            return remote.getAddress().getHostAddress();
        }
        return null;
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
        // 요청 ID를 백엔드로 전파해 게이트웨이↔resource-api 로그를 같은 키로 묶는다.
        writable.set(REQUEST_ID_HEADER, requestIdOf(exchange));
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                return writable;
            }
        };
    }

    /** fail-close(인증): 401로 즉시 응답하고 체인을 끊는다(백엔드 미전달). */
    private Mono<Void> reject401(ServerWebExchange exchange, String reason) {
        log.info("authn reject=401 reason=\"{}\" method={} path={} requestId={}", reason,
                exchange.getRequest().getMethod(), exchange.getRequest().getPath(), requestIdOf(exchange));
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
