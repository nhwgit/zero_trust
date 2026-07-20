package com.ztg.gateway.risk;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.LocalTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ztg.common.model.RiskSignals;
import com.ztg.common.net.CidrRanges;
import com.ztg.gateway.config.TrustedProxiesProperties;

import reactor.core.publisher.Mono;

/**
 * 이번 요청의 위험 신호를 관측해 {@link com.ztg.common.model.DecisionRequest#context()}에 실을 맵으로 만든다.
 * IP 두 축의 산출 지점 — 논리 축(source-ip: 신뢰 프록시의 XFF 첫 홉, 아니면 소켓 피어)과
 * 네트워크 축(network-ip: 항상 소켓 피어 = 커널(XDP)이 보는 좌표)을 여기서만 계산한다.
 *
 * <p>신호 부재는 키를 비워 두고 수신 쪽이 중립값으로 폴백한다(부재는 가중 아님).
 * 반환이 Mono인 이유: 레이트 관측이 다중 GW 모드에선 Redis 공유 집계(네트워크 I/O)라서다.
 */
@Component
public class RiskContextObserver {

    /** 프록시가 실제 출발지를 남기는 표준 헤더(첫 홉이 원 클라이언트). */
    public static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";

    private final RateObserver rateObserver;
    private final CidrRanges trustedProxies;
    private final Clock clock;

    public RiskContextObserver(RateObserver rateObserver, TrustedProxiesProperties trustedProxiesProperties, Clock clock) {
        this.rateObserver = rateObserver;
        this.trustedProxies = CidrRanges.parse(trustedProxiesProperties.trustedProxies(), "ztg.gateway.trusted-proxies");
        this.clock = clock;
    }

    /** 게이트웨이는 캐시 히트 포함 모든 요청을 보므로 레이트의 권위 관측자다(소유권은 RateObserver 구현이 결정). */
    public Mono<Map<String, String>> observe(ServerWebExchange exchange, String subject) {
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
     * 논리 축 IP. XFF는 자기 신고 값이라 소켓 피어가 신뢰 프록시 목록에 들 때만 첫(가장 왼쪽) 항목을
     * 원 클라이언트로 인정한다 — 무조건 믿으면 위조 XFF로 ip-change 회피·상태 오염이 가능하다.
     * 비신뢰 발신은 소켓 피어 그대로, 그마저 없으면 {@code null}(신호 부재).
     */
    private String clientIp(ServerHttpRequest request, InetAddress peer) {
        String forwarded = request.getHeaders().getFirst(FORWARDED_FOR_HEADER);
        if (forwarded != null && !forwarded.isBlank() && peer != null && trustedProxies.contains(peer)) {
            return forwarded.split(",", 2)[0].trim();
        }
        return peer != null ? peer.getHostAddress() : null;
    }
}
