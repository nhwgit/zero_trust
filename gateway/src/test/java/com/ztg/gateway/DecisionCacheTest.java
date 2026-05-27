package com.ztg.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;

/**
 * {@link DecisionCache} 단위 테스트 — 값 동등성 키, enabled 토글, 키 충돌 없음을 시간에 의존하지 않고 검증.
 * (TTL 만료는 타이밍에 민감해 단위 테스트에서 다루지 않는다 — TTL=0/매우 짧게 두는 통합 측정으로 확인.)
 */
class DecisionCacheTest {

    private static DecisionRequest request(String subject, String path) {
        return new DecisionRequest(subject, "GET", path, Map.of());
    }

    @Test
    void servesCachedDecisionForValueEqualRequest() {
        DecisionCache cache = new DecisionCache(true, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        DecisionResponse stored = DecisionResponse.deny("policy");

        // 키는 값 동등성: put에 쓴 인스턴스와 다른(그러나 값이 같은) 인스턴스로도 히트해야 한다.
        cache.put(request("alice", "/api/hello"), stored);
        assertThat(cache.getIfPresent(request("alice", "/api/hello"))).isSameAs(stored);
    }

    @Test
    void missesForDifferentSubjectOrResource() {
        DecisionCache cache = new DecisionCache(true, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        cache.put(request("alice", "/api/hello"), DecisionResponse.deny("policy"));

        assertThat(cache.getIfPresent(request("bob", "/api/hello"))).isNull();      // 다른 subject
        assertThat(cache.getIfPresent(request("alice", "/api/payroll"))).isNull();  // 다른 resource
    }

    @Test
    void disabledCacheNeverStores() {
        DecisionCache cache = new DecisionCache(false, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        cache.put(request("alice", "/api/hello"), DecisionResponse.deny("policy"));

        assertThat(cache.getIfPresent(request("alice", "/api/hello"))).isNull();
    }
}
