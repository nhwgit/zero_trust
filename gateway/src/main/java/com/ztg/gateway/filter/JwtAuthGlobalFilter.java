package com.ztg.gateway.filter;

import com.ztg.gateway.client.PdpClient;
import com.ztg.gateway.config.TrustedProxiesProperties;
import com.ztg.gateway.risk.RateObserver;
import java.net.InetAddress;
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
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.web.GatewayTrust;
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

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. resource-api가 동일 값을 검증한다(규약 정본은 공용 상수). */
    public static final String TRUST_HEADER = GatewayTrust.HEADER;
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

    private final ReactiveJwtDecoder jwtDecoder;
    private final PdpClient pdpClient;
    private final String trustSecret;
    private final TrustedProxies trustedProxies;
    private final MeterRegistry meterRegistry;
    private final RateObserver rateObserver;
    private final Clock clock;

    JwtAuthGlobalFilter(ReactiveJwtDecoder jwtDecoder,
                        PdpClient pdpClient,
                        @Value("${ztg.gateway.trust-secret}") String trustSecret,
                        TrustedProxiesProperties trustedProxiesProperties,
                        MeterRegistry meterRegistry,
                        RateObserver rateObserver,
                        Clock clock) {
        this.jwtDecoder = jwtDecoder;
        this.pdpClient = pdpClient;
        this.trustSecret = trustSecret;
        this.trustedProxies = TrustedProxies.fromCidrs(trustedProxiesProperties.trustedProxies());
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
        // PEP가 본 요청 맥락(출발지 IP·레이트·시각)을 위험 신호로 실어 PDP→PIP까지 전달한다.
        // 다중 GW 모드의 레이트 관측은 Redis 공유 집계(비동기 I/O)라 맥락 구성부터 리액티브 체인이다.
        return observeRiskContext(exchange, subject)
                .map(context -> new DecisionRequest(subject, method, path, context))
                .flatMap(request -> decide(request, requestId))
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

    /** PDP 호출(지연 측정 포함). fail-close: 호출 실패는 "판단 불가"이므로 DENY로 환산한다. */
    private Mono<DecisionResponse> decide(DecisionRequest request, String requestId) {
        // PDP 호출 지연을 측정한다(p99는 application.yml의 히스토그램 설정으로 산출).
        Timer.Sample sample = Timer.start(meterRegistry);
        // 요청ID를 헤더로 실어 PDP/PIP 로그까지 같은 ID로 묶는다(분산 추적).
        return pdpClient.decide(request, requestId)
                .doOnNext(d -> sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "success")))
                .onErrorResume(e -> {
                    sample.stop(meterRegistry.timer("ztg.pdp.requests", "outcome", "error"));
                    return Mono.just(DecisionResponse.deny(PDP_UNAVAILABLE_PREFIX + e.getMessage()));
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
     *   <li><b>source-ip</b>: 출발지 IP(논리 축). 신뢰 프록시가 단 {@code X-Forwarded-For}면 첫 홉, 아니면 소켓 원격주소.
     *       PIP가 직전 관측과 비교해 IP 변화를 가중하고, 캐시 키에도 반영돼 <b>새 IP는 자동 미스</b>가 된다.</li>
     *   <li><b>network-ip</b>: 소켓 피어 IP(네트워크 축) — 커널(XDP)이 패킷에서 보는 것과 같은 좌표.
     *       LB/프록시 뒤에선 논리 축과 달라지므로, PIP의 L4 신호↔주체 번역은 이 축으로 한다.
     *       (직결이면 source-ip와 동일 — 캐시 키에 포함돼도 키가 갈리지 않고, LB 뒤에선 LB IP로 안정적.)</li>
     *   <li><b>requests-in-window</b>: 이 주체의 슬라이딩 윈도우 요청 수(레이트 급증 신호). 매 요청 달라지는
     *       휘발성 값이라 캐시 키에선 제외한다({@link com.ztg.gateway.cache.DecisionCache} 키 설계 참조) — 급증은 epoch 능동 무효화로 처리.</li>
     *   <li><b>hour-of-day</b>: 요청 시각의 시(업무시간 외 신호). 주입 시계로 산출해 테스트에서 고정 가능.</li>
     * </ul>
     *
     * 신호 부재(IP 미상 등)는 키를 비워 두고, PDP/PIP 쪽에서 중립값으로 폴백한다(부재는 가중 아님).
     *
     * <p>반환이 Mono인 이유: 레이트 관측이 다중 GW 모드에선 Redis 공유 집계(네트워크 I/O)라
     * 이벤트 루프를 막지 않는 리액티브 체인이어야 한다(단일 GW 기본은 즉시 완료되는 로컬 카운터).
     */
    private Mono<Map<String, String>> observeRiskContext(ServerWebExchange exchange, String subject) {
        // 게이트웨이는 캐시 히트 포함 모든 요청을 보므로 여기서 레이트를 센다(권위 관측자 —
        // 소유권은 RateObserver 구현이 정한다: 단일 GW=노드-로컬, 다중 GW=Redis 공유 집계).
        return rateObserver.observe(subject).map(requestsInWindow -> {
            Map<String, String> context = new LinkedHashMap<>();
            InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
            InetAddress peer = remote != null ? remote.getAddress() : null;
            String sourceIp = clientIp(exchange.getRequest(), peer);
            if (sourceIp != null) {
                context.put(RiskSignals.CTX_SOURCE_IP, sourceIp);
            }
            if (peer != null) {
                context.put(RiskSignals.CTX_NETWORK_IP, peer.getHostAddress());
            }
            context.put(RiskSignals.CTX_REQUESTS_IN_WINDOW, Integer.toString(requestsInWindow));
            context.put(RiskSignals.CTX_HOUR_OF_DAY, Integer.toString(LocalTime.now(clock).getHour()));
            return context;
        });
    }

    /**
     * 출발지 IP(논리 축)를 고른다. XFF는 발신자가 임의로 쓸 수 있는 자기 신고 값이라, 소켓 원격주소가
     * 신뢰 프록시 목록({@code ztg.gateway.trusted-proxies})에 들 때만 첫(가장 왼쪽) 항목을
     * 원 클라이언트로 인정한다 — 무조건 믿으면 XFF 고정으로 ip-change 신호를 영영 회피하거나
     * XFF 회전으로 캐시·PIP 상태를 오염시킬 수 있다. 비신뢰 발신(원격주소 미상 포함)은 소켓
     * 원격주소를 그대로 쓰고, 그마저 없으면 {@code null}(신호 부재).
     *
     * @param peer 소켓 피어 주소(호출부가 이미 꺼낸 값 — 네트워크 축 관측과 공유), {@code null}=미상
     */
    private String clientIp(ServerHttpRequest request, InetAddress peer) {
        String forwarded = request.getHeaders().getFirst(FORWARDED_FOR_HEADER);
        if (forwarded != null && !forwarded.isBlank() && peer != null && trustedProxies.isTrusted(peer)) {
            // "client, proxy1, proxy2" → 첫 홉만. 프록시가 덧붙이므로 가장 왼쪽이 원 클라이언트다.
            return forwarded.split(",", 2)[0].trim();
        }
        return peer != null ? peer.getHostAddress() : null;
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

    /** fail-close(인가): 403으로 즉시 응답하고 사유를 헤더로 노출한다(백엔드 미전달). 로그는 호출부(DENY info)가 남긴다. */
    private Mono<Void> reject403(ServerWebExchange exchange, String reason) {
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
