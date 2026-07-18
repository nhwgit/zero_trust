package com.ztg.gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * XFF 신뢰 경계 설정({@code ztg.gateway.trusted-proxies}) 바인딩 — 소켓 원격주소가 이
 * 목록(IP/CIDR)에 들 때만 {@code X-Forwarded-For}를 출발지 IP로 인정한다
 * ({@link com.ztg.gateway.filter.JwtAuthGlobalFilter} 참조).
 *
 * <p>기본값은 loopback 신뢰 — 모든 데모/스모크가 localhost 경유 XFF 주입으로 IP 변화를
 * 시뮬레이션하므로 기존 스크립트가 무수정 호환된다. 운영이라면 빈 목록(fail-safe: XFF 전면
 * 무시)에서 시작해 실제 LB/프록시 대역만 명시하는 것이 맞다(트레이드오프는 설계 메모 참조).
 */
@ConfigurationProperties("ztg.gateway")
public record TrustedProxiesProperties(
        @DefaultValue({"127.0.0.0/8", "::1/128"}) List<String> trustedProxies) {
}
