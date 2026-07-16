package com.ztg.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;

import com.ztg.common.model.Decision;
import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskSignals;

/**
 * {@link DecisionCache} 단위 테스트 — 값 동등성 키, 휘발성 레이트 제외, source-ip 분기, enabled 토글에 더해
 * 능동 무효화(주체 epoch 키), 위험적응 TTL, 가득 참 시 고아 회수(sweep)와 그 스로틀을 검증한다.
 * 시간 의존 테스트는 단조 시계를 주입해 결정적으로 둔다.
 */
class DecisionCacheTest {

    /** 기본 캐시: base TTL 60s, 고위험 TTL 1s(score≥50), 폭주 진입>60/해제≤40, 크기 100. 시계 미주입(실시간, 만료 안 걸림). */
    private static DecisionCache cache(boolean enabled) {
        return cache(enabled, System::nanoTime);
    }

    private static DecisionCache cache(boolean enabled, LongSupplier nanoClock) {
        return new DecisionCache(enabled, Duration.ofSeconds(60), Duration.ofSeconds(1), 50, 60, 40, 100,
                Duration.ofSeconds(1), new SimpleMeterRegistry(), nanoClock);
    }

    /** sweep 검증용 소형 캐시: 크기 2, sweep 간격 지정. 그 외는 기본 캐시와 동일. */
    private static DecisionCache smallCache(Duration sweepInterval, LongSupplier nanoClock) {
        return new DecisionCache(true, Duration.ofSeconds(60), Duration.ofSeconds(1), 50, 60, 40, 2,
                sweepInterval, new SimpleMeterRegistry(), nanoClock);
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
        // 레이트 신호는 매 요청 달라지지만 캐시 키에서 제외되므로, 나머지 맥락이 같으면 히트해야 한다.
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
        // 능동 무효화: 위험 상승으로 epoch가 오르면 그 주체의 옛 엔트리가 한 번에 키-아웃된다.
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

    @Test
    void rateBandCrossingForcesMissEvenWhenKeyMatches() {
        // 휘발성 레이트는 키에서 빠져 있어 같은 IP·경로면 키가 동일하다. 그래도 레이트가 폭주 밴드로
        // 전이하면(임계 60 초과) 그 한 요청은 강제 미스가 돼 재평가(PDP 왕복)를 유발해야 한다 = 급증 트리거.
        DecisionCache cache = cache(true);
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), DecisionResponse.allow("ok"));

        // 같은 키(IP·경로 동일, 레이트만 정상 밴드) → 히트, 그리고 직전 밴드=정상으로 기록된다.
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "5")).isAllowed())
                .isTrue();
        // 레이트가 폭주 밴드로 전이(5→99) → 키가 같아도 강제 미스(null) → 게이트웨이가 PDP를 다시 부른다.
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "99"))).isNull();
    }

    @Test
    void sustainedBurstDoesNotKeepBypassing() {
        // 엣지 트리거 확인: 밴드가 폭주로 한 번 전이한 뒤 폭주가 지속되면(밴드 불변) 더는 바이패스하지 않고
        // 캐시가 정상 동작한다. 레벨 트리거였다면 폭주 내내 캐시가 죽어 부하 데모가 무너진다.
        DecisionCache cache = cache(true);
        // 정상 밴드 기준 설정.
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), DecisionResponse.allow("ok"));
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1")).isAllowed())
                .isTrue();
        // 정상→폭주 전이: 강제 미스. 이 미스가 유발한 재평가 결과를 캐시에 적재했다고 가정.
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "99"))).isNull();
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "99"), DecisionResponse.deny("burst"));

        // 폭주 지속(밴드 불변=폭주) → 전이 아님 → 적재된 결정이 히트한다(엣지 트리거).
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "120")).isAllowed())
                .isFalse();
    }

    @Test
    void oscillationAroundEnterThresholdDoesNotKeepBypassing() {
        // 히스테리시스 확인: 폭주 진입(>60) 후 레이트가 진입 임계 경계에서 진동(55↔70)해도 사이 구간(40<r≤60)은
        // 직전 밴드를 유지해 전이가 아니다 → 바이패스 없이 캐시가 동작한다. 단일 임계였다면 매 진동이 전이=바이패스.
        DecisionCache cache = cache(true);
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1"), DecisionResponse.allow("ok"));
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "1")).isAllowed())
                .isTrue();                                                                        // 기준: 정상 밴드
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "70"))).isNull(); // 진입: 전이 1회
        cache.put(requestWithCtx("alice", "/api/hello", "203.0.113.7", "70"), DecisionResponse.deny("burst"));

        // 사이 구간으로 내려와도(55≤60) 밴드 유지 → 전이 아님 → 히트. 다시 70으로 올라가도 마찬가지.
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "55")).isAllowed())
                .isFalse();
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "70")).isAllowed())
                .isFalse();

        // 해제 임계(≤40)까지 내려와야 정상 밴드로 전이 → 그 한 요청만 강제 미스(재평가로 점수 하향을 반영할 기회).
        assertThat(cache.getIfPresent(requestWithCtx("alice", "/api/hello", "203.0.113.7", "35"))).isNull();
    }

    @Test
    void remoteEpochFromFanoutKeysOutPriorEntriesWithoutLocalPdpRoundtrip() {
        // 다중 GW 능동 무효화: 이 노드가 alice로 PDP를 다녀온 적 없어도(epoch 학습은 0), 다른 GW가 유발한
        // epoch 상승을 Redis fan-out으로 받으면 그 주체의 옛 ALLOW가 즉시 키-아웃돼 다음 조회는 미스가 된다.
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isTrue();

        // 다른 노드에서 위험이 올라 PIP가 epoch=1로 bump → fan-out 수신(이 노드는 PDP 왕복 없이 학습 epoch만 상승).
        cache.applyRemoteEpoch("alice", 1L);

        // 같은 세션·재로그인 없이 옛 epoch=0 엔트리는 더는 조회되지 않는다 → 미스(재평가 강제).
        assertThat(cache.getIfPresent(request("alice", "/api/a"))).isNull();
        // 다른 주체(bob)는 영향 없음 — fan-out은 주체별.
        cache.put(request("bob", "/api/a"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("bob", "/api/a")).isAllowed()).isTrue();
    }

    @Test
    void staleRemoteEpochDoesNotResurrectKeyedOutEntries() {
        // fan-out 메시지가 순서 뒤바뀌거나 중복돼 더 낮은 epoch가 와도 단조 학습이라 되돌아가지 않는다.
        DecisionCache cache = cache(true);
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 2));   // knownEpoch=2 학습
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isTrue();

        cache.applyRemoteEpoch("alice", 1L);   // 뒤늦은 낮은 epoch — knownEpoch를 되돌리면 안 됨

        // /a(epoch=2)는 여전히 살아 있다(낮은 fan-out이 학습 epoch를 깎지 못했다는 증거).
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isTrue();
    }

    @Test
    void fullCacheReclaimsExpiredOrphansOnPut() {
        // 공격 시나리오: source-ip는 키에 남으므로 IP를 회전시키면 매번 새 키가 적재된다. 그 엔트리들은
        // 다시 조회될 키가 아니라(고아) lazy 제거가 영영 안 걸리고, sweep이 없으면 max-size 영구 점유로
        // put이 계속 거부돼 캐시가 사실상 off가 된다(epoch 키-아웃 고아도 같은 경로로 회수된다).
        AtomicLong nanos = new AtomicLong(1_000_000_000L);
        DecisionCache cache = smallCache(Duration.ofSeconds(1), nanos::get);   // 크기 2
        cache.put(requestWithCtx("mallory", "/api/hello", "10.0.0.1", "1"), decision(Decision.ALLOW, 10, 0));
        cache.put(requestWithCtx("mallory", "/api/hello", "10.0.0.2", "1"), decision(Decision.ALLOW, 10, 0));

        // 가득 + 전부 미만료: sweep이 돌아도 회수할 게 없어 적재 생략(기존 크기상한 동작 유지).
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("alice", "/api/a"))).isNull();

        // TTL(60s) 경과 → 고아 만료. 다음 put이 sweep으로 자리를 되찾아 정상 적재된다 = 캐시 정지는 TTL로 바운드.
        nanos.addAndGet(Duration.ofSeconds(61).toNanos());
        cache.put(request("alice", "/api/a"), decision(Decision.ALLOW, 10, 0));
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isTrue();
    }

    @Test
    void sweepIsThrottledToMinimumInterval() {
        // 2차 DoS 방지: 미만료 엔트리로 계속 가득 채워도 매 put이 O(n) 스캔을 유발하지 않는다 —
        // sweep은 최소 간격(여기선 60s) 이내 재진입 시 스캔 없이 건너뛰고, 간격이 지나야 다시 회수한다.
        AtomicLong nanos = new AtomicLong(1_000_000_000L);
        DecisionCache cache = smallCache(Duration.ofSeconds(60), nanos::get);  // 크기 2, 간격 60s
        // 고위험(score≥50) 결정은 TTL 1s → 금방 만료돼 회수 대상이 된다.
        cache.put(requestWithCtx("mallory", "/api/hello", "10.0.0.1", "1"), decision(Decision.DENY, 90, 0));
        cache.put(requestWithCtx("mallory", "/api/hello", "10.0.0.2", "1"), decision(Decision.DENY, 90, 0));

        nanos.addAndGet(Duration.ofSeconds(2).toNanos());                      // 고아 만료
        cache.put(request("alice", "/api/a"), decision(Decision.DENY, 90, 0)); // sweep 1회차: 회수 → 적재 성공
        assertThat(cache.getIfPresent(request("alice", "/api/a")).isAllowed()).isFalse();
        cache.put(requestWithCtx("mallory", "/api/hello", "10.0.0.3", "1"), decision(Decision.DENY, 90, 0)); // 다시 가득

        nanos.addAndGet(Duration.ofSeconds(2).toNanos());                      // 또 만료됐지만 간격(60s) 이내
        cache.put(request("bob", "/api/b"), decision(Decision.DENY, 90, 0));   // sweep 스킵 → 적재 생략
        assertThat(cache.getIfPresent(request("bob", "/api/b"))).isNull();

        nanos.addAndGet(Duration.ofSeconds(61).toNanos());                     // 간격 경과 → 다시 회수 가능
        cache.put(request("bob", "/api/b"), decision(Decision.DENY, 90, 0));
        assertThat(cache.getIfPresent(request("bob", "/api/b")).isAllowed()).isFalse();
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
