package com.ztg.gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * XFF 신뢰 경계 설정({@code ztg.gateway.trusted-proxies}) 바인딩 — 소켓 원격주소가 이
 * 목록(IP/CIDR)에 들 때만 {@code X-Forwarded-For}를 출발지 IP로 인정한다.
 * 기본값은 loopback 신뢰(데모/스모크의 localhost XFF 주입 호환); 빈 목록이면 XFF 전면 무시(fail-safe).
 */
@ConfigurationProperties("ztg.gateway")
public record TrustedProxiesProperties(
        @DefaultValue({"127.0.0.0/8", "::1/128"}) List<String> trustedProxies) {
}
