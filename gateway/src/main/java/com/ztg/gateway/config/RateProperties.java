package com.ztg.gateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 주체별 레이트 관측 설정({@code ztg.gateway.rate.*}) 바인딩. 임계는 PIP의
 * {@code ztg.pip.risk.burst-*}와 같은 값으로 둬야 강제 재평가와 점수 변화가 정합된다.
 */
@ConfigurationProperties("ztg.gateway.rate")
public record RateProperties(
        @DefaultValue("10s") Duration window,
        @DefaultValue("60") int burstThreshold,
        @DefaultValue("40") int burstExitThreshold) {
}
