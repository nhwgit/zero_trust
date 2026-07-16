package com.ztg.gateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 결정 캐시 설정({@code ztg.gateway.decision-cache.*}) 바인딩. 항목별 의미와 설계 근거는
 * {@link com.ztg.gateway.cache.DecisionCache} 클래스 문서 참조. {@code @Value} 나열 대신 record로
 * 묶어 생성자 비대를 막고, 테스트가 설정 묶음을 값으로 만들어 주입할 수 있게 한다.
 */
@ConfigurationProperties("ztg.gateway.decision-cache")
public record DecisionCacheProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("5s") Duration ttl,
        @DefaultValue("1s") Duration highRiskTtl,
        @DefaultValue("50") int highRiskScore,
        @DefaultValue("10000") int maxSize,
        @DefaultValue("1s") Duration sweepInterval) {
}
