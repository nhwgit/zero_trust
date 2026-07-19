package com.ztg.gateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 결정 캐시 설정({@code ztg.gateway.decision-cache.*}) 바인딩. 항목별 의미는
 * {@link com.ztg.gateway.cache.DecisionCache} 클래스 문서 참조.
 */
@ConfigurationProperties("ztg.gateway.decision-cache")
public record DecisionCacheProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("5s") Duration ttl,
        @DefaultValue("1s") Duration highRiskTtl,
        @DefaultValue("50") int highRiskScore,
        @DefaultValue("10000") int maxSize,
        @DefaultValue("1s") Duration sweepInterval,
        @DefaultValue("60s") Duration epochForgetAfter) {

    public DecisionCacheProperties {
        // epoch 망각이 엔트리 수명보다 짧으면, 망각으로 조회 세대가 과거로 돌아갔을 때 아직 살아 있는
        // 옛 세대 엔트리(stale ALLOW)가 부활할 수 있다 — 모든 엔트리가 먼저 만료됨을 기동 시점에 강제.
        Duration maxEntryTtl = ttl.compareTo(highRiskTtl) >= 0 ? ttl : highRiskTtl;
        if (epochForgetAfter.compareTo(maxEntryTtl) < 0) {
            throw new IllegalArgumentException(
                    "epoch-forget-after (%s) must be >= max(ttl, high-risk-ttl) (%s)"
                            .formatted(epochForgetAfter, maxEntryTtl));
        }
    }
}
