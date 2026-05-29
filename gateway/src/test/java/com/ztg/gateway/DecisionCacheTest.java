package com.ztg.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;

import com.ztg.common.Decision;
import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.RiskSignals;

/**
 * {@link DecisionCache} 단위 테스트 — 값 동등성 키, 휘발성 레이트 제외, source-ip 분기, enabled 토글에 더해
 * D1 능동 무효화(주체 epoch 키)와 위험적응 TTL을 검증한다. 시간 의존 테스트는 단조 시계를 주입해 결정적으로 둔다.
 */
class DecisionCacheTest {

    /** 기본 캐시: base TTL 60s, 고위험 TTL 1s(score≥50), 크기 100. 시계 미주입(실시간, 만료 안 걸림). */
    private static DecisionCache cache(boolean enabled) {
        return cache(enabled, System::nanoTime);
    }

    private static DecisionCache cache(boolean enabled, LongSupplier nanoClock) {
        return new DecisionCache(enabled, Duration.ofSeconds(60), Duration.ofSeconds(1), 50, 100,
                new SimpleMeterRegistry(), nanoClock);
    }

    private static DecisionRequest request(String subject, String path) {
        return new DecisionRequest(subject, "GET", path, Map.of());
    }

    /** 점수/epoch를 명시한 결정(위험적응 TTL·epoch 키 검증용). */
    private static DecisionResponse decision(Decision d, int score, long epoch) {
        return new DecisionResponse(d, d == Decision.ALLOW ? "ok" : "denied", score, List.of(), epoch);
    }

    @Test
    void servesCachedDecisionForValueEqualRequest() {
        DecisionCache cache = cache(true);
        DecisionResponse stored = DecisionResponse.deny("policy");

        // 키는 값 동등성: put에 쓴 인스턴스와 다른(그러나 값이 같은) 인스턴스로도 히트해야 한다.
        cache.put(request("alice", "/api/hello"), stored);
        assertThat(cache.getIfPresent(request("alice", "/api/hello"))).isSameAs(stored);
    }

    @Test
    void missesForDifferentSubjectOrResource() {
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/hello"), DecisionResponse.deny("policy"));

        assertThat(cache.getIfPresent(request("bob", "/api/hello"))).isNull();      // 다른 subject
        assertThat(cache.getIfPresent(request("alice", "/api/payroll"))).isNull();  // 다른 resource
    }

    @Test
    void hitsWhenOnlyVolatileRateDiffers() {
        // 레이트 신호는 매 요청 달라지지만 캐시 키에서 제외되므로, 나머지 맥락이 같으면 히트해야 한다(결정 #3).
        DecisionCache cache = cache(true);
        DecisionResponse stored = DecisionResponse.allow("ok");
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), stored);

        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "99")))
                .isSameAs(stored);
    }

    @Test
    void missesWhenSourceIpDiffers() {
        // source-ip는 키에 남아 새 IP는 자동 미스 → 재평가(전방호환).
        DecisionCache cache = cache(true);
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), DecisionResponse.allow("ok"));

        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "198.51.100.9", "1"))).isNull();
    }

    @Test
    void evictsPriorEntriesWhenSubjectEpochAdvances() {
        // 능동 무효화(결정 #1): 위험 상승으로 epoch가 오르면 그 주체의 옛 엔트리가 한 번에 키-아웃된다.
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 0));
        cache.put(request("alice", "/api/b"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isTrue();
        assertThat(cache.getIfPresent(request("alice", "/api/b")).isAllowed()).isTrue();

        // PIP가 위험 변화를 감지해 epoch=1로 올린 새 DENY가 /a 경로로 도착 → 게이트웨이가 학습.
        cache.put(request("alice", "/api/a"), decision(Decision.DENY, 85, 1));

        // 같은 세션·재로그인 없이 /a는 ALLOW→DENY로 전이한다(옛 ALLOW는 키-아웃).
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isFalse();
        // epoch 상승은 /b까지 전파: 옛 epoch=0 엔트리는 더는 조회되지 않아 미스 → 재평가 강제.
        assertThat(cache.getIfPresent(request("alice", "/api/b"))).isNull();
        // 다른 주체(bob)는 영향 없음 — epoch는 주체별.
        cache.put(request("bob", "/api/a"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("bob", "/api/a")).isAllowed()).isTrue();
    }

    @Test
    void learnedEpochIsMonotonicAgainstOutOfOrderDecisions() {
        // 역전파가 뒤바뀌어 도착해도 더 작은 epoch로 되돌아가지 않는다(옛 엔트리 부활 방지).
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 1));   // epoch=1에 적재
        cache.put(request("alice", "/api/x"), decision(Decision.DENY, 90, 2));    // knownEpoch=2로 상승

        // 뒤늦게 도착한 낮은 epoch(1) 결정 — knownEpoch를 1로 되돌리면 안 된다.
        cache.put(request("alice", "/api/b"), decision(Decision.ALLOW, 10, 1));

        // /a의 epoch=1 엔트리는 여전히 키-아웃 상태(knownEpoch가 2로 유지됐다는 증거).
        assertThat(cache.getIfPresent(request("alice", "/api/a"))).isNull();
    }

    @Test
    void staleLowerEpochDecisionDoesNotClobberFresherEntry() {
        // 위험 전이 경합(fail-close): 신선한 DENY(epoch1) 뒤에 뒤늦은 stale ALLOW(epoch0)가 도착해도
        // 그 ALLOW는 옛 세대 키에 고립돼 DENY를 덮지 못한다 — put이 value.epoch()로 키잉하기 때문.
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/a"), decision(Decision.DENY, 85, 1));   // 신선한 차단
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 0));  // 뒤늦은 stale 허용

        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isFalse();
    }

    @Test
    void highRiskDecisionExpiresSoonerThanLowRisk() {
        // 위험적응 TTL: 고위험(score≥50)은 1s, 저위험은 60s. 2s 경과 후 고위험만 만료된다.
        AtomicLong nanos = new AtomicLong(1_000_000_000L);
        DecisionCache cache = cache(true, nanos::get);
        cache.put(request("alice", "/api/low"), decision(Decision.ALLOW, 10, 0));   // 저위험 → 60s
        cache.put(request("bob", "/api/high"), decision(Decision.DENY, 90, 0));     // 고위험 → 1s

        nanos.addAndGet(Duration.ofSeconds(2).toNanos());                           // 2초 경과

        assertThat(cache.getIfPresent(request("bob", "/api/high"))).isNull();       // 고위험 만료
        assertThat(cache.getIfPresent(request("alice", "/api/low")).isAllowed()).isTrue();  // 저위험 생존
    }

    private static DecisionRequest requestWithCtx(String subject, String path, String ip, String rate) {
        return new DecisionRequest(subject, "GET", path, Map.of(
                RiskSignals.CTX_SOURCE_IP, ip,
                RiskSignals.CTX_REQUESTS_IN_WINDOW, rate));
    }

    @Test
    void disabledCacheNeverStores() {
        DecisionCache cache = cache(false);
        cache.put(request("alice", "/api/hello"), DecisionResponse.deny("policy"));

        assertThat(cache.getIfPresent(request("alice", "/api/hello"))).isNull();
    }
}
