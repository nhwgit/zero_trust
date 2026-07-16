package com.ztg.gateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 주체별 레이트 관측 설정({@code ztg.gateway.rate.*}) 바인딩 — 슬라이딩 윈도우 길이
 * ({@link com.ztg.gateway.risk.SubjectRateObserver})와 폭주 밴드 이중 임계(캐시 바이패스 트리거,
 * {@link com.ztg.gateway.cache.DecisionCache}).
 *
 * <p>임계는 PIP의 {@code ztg.pip.risk.burst-*}와 같은 값으로 둬야 게이트웨이가 전이로 판정한
 * 강제 재평가가 PIP에서 같은 방향의 점수 변화로 이어진다(임계 정합은 배포 설정의 몫).
 */
@ConfigurationProperties("ztg.gateway.rate")
public record RateProperties(
        @DefaultValue("10s") Duration window,
        @DefaultValue("60") int burstThreshold,
        @DefaultValue("40") int burstExitThreshold) {
}
