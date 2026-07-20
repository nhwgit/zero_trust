package com.ztg.gateway.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import reactor.netty.http.server.ProxyProtocolSupportType;

/**
 * PROXY protocol 수신 게이트({@code ztg.gateway.proxy-protocol.enabled=true} 전용) — 켜면 Netty가
 * 연결 선두의 PP 헤더(v1/v2)를 해석해 remoteAddress를 광고된 원 클라이언트 주소로 바꾼다.
 * AUTO 모드라 PP 없는 직결 연결도 같은 포트에서 종전대로 동작한다(헬스체크·직결 데모 공존).
 * 광고 값의 신뢰 판정(위조 PP 기각)은 {@link com.ztg.gateway.risk.EdgePeerResolver} 몫 — 여기선 해석만.
 */
@Configuration
@ConditionalOnProperty(name = "ztg.gateway.proxy-protocol.enabled", havingValue = "true")
class ProxyProtocolConfig {

    @Bean
    NettyServerCustomizer proxyProtocolServerCustomizer() {
        return server -> server.proxyProtocol(ProxyProtocolSupportType.AUTO);
    }
}
