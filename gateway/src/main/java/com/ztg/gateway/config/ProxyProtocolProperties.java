package com.ztg.gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * PROXY protocol 수신 설정({@code ztg.gateway.proxy-protocol}) 바인딩 — LB 에지 관측 배치에서
 * L4 LB가 PP 헤더로 넘긴 원 클라이언트 좌표를 네트워크 축으로 쓸지의 게이트.
 * PP 헤더도 자기 신고 값이라 소켓 피어가 {@code trusted-senders}(LB 대역, IP/CIDR)에 들 때만 인정한다.
 * 기본 off + 빈 목록 = 직결 배치의 기존 경로 무변경(fail-safe).
 */
@ConfigurationProperties("ztg.gateway.proxy-protocol")
public record ProxyProtocolProperties(
        @DefaultValue("false") boolean enabled,
        @DefaultValue List<String> trustedSenders) {
}
