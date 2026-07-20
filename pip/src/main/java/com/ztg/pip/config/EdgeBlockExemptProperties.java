package com.ztg.pip.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 에지 차단 제외 대역({@code ztg.pip.edge-block-exempt}) 바인딩 — 이 목록(IP/CIDR)에 든 소스 IP의
 * L4 신호는 세션 축 재평가만 수행하고 에지 차단 지시(enforcement)를 생략한다(LB IP 오폭 방지).
 * 기본 빈 목록 = 모든 신호 IP에 종전대로 차단 지시(직결 배치).
 */
@ConfigurationProperties("ztg.pip")
public record EdgeBlockExemptProperties(@DefaultValue List<String> edgeBlockExempt) {
}
