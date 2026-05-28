package com.ztg.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.RiskSignals;

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
    void hitsWhenOnlyVolatileRateDiffers() {
        // 레이트 신호는 매 요청 달라지지만 캐시 키에서 제외되므로, 나머지 맥락이 같으면 히트해야 한다(결정 #3).
        DecisionCache cache = new DecisionCache(true, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        DecisionResponse stored = DecisionResponse.allow("ok");
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), stored);

        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "99")))
                .isSameAs(stored);
    }

    @Test
    void missesWhenSourceIpDiffers() {
        // source-ip는 키에 남아 새 IP는 자동 미스 → 재평가(전방호환).
        DecisionCache cache = new DecisionCache(true, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), DecisionResponse.allow("ok"));

        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "198.51.100.9", "1"))).isNull();
    }

    private static DecisionRequest requestWithCtx(String subject, String path, String ip, String rate) {
        return new DecisionRequest(subject, "GET", path, Map.of(
                RiskSignals.CTX_SOURCE_IP, ip,
                RiskSignals.CTX_REQUESTS_IN_WINDOW, rate));
    }

    @Test
    void disabledCacheNeverStores() {
        DecisionCache cache = new DecisionCache(false, Duration.ofSeconds(60), 100, new SimpleMeterRegistry());
        cache.put(request("alice", "/api/hello"), DecisionResponse.deny("policy"));

        assertThat(cache.getIfPresent(request("alice", "/api/hello"))).isNull();
    }
}
