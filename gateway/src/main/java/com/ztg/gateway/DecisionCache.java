package com.ztg.gateway;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.RiskSignals;

/**
 * PEP(Gateway)가 직전 인가 결정을 짧게 캐싱해, 같은 요청이 다시 오면 PDP 왕복을 건너뛰게 한다.
 *
 * <p><b>키:</b> {@link DecisionRequest} 값(subject+action+resource+context)에서 <b>휘발성 레이트 신호를
 * 뺀</b> 정규화 요청 + <b>주체의 현재 epoch</b>. {@code source-ip}·{@code hour-of-day}는 키에 남겨 새 IP/시간대는
 * 자동 캐시 미스 → 재평가가 되지만, {@code requests-in-window}는 매 요청 달라져 키에 넣으면 캐시가 통째로
 * 무력화되므로 제외한다(README 결정 #3). 레이트 급증은 키 분기가 아니라 <b>능동 무효화(epoch bump)</b>로 처리한다.
 *
 * <p><b>능동 무효화 = 주체별 epoch 키(README 결정 #1):</b> PIP가 위험 변화를 감지하면 epoch를 +1 해
 * {@link DecisionResponse#epoch()}로 게이트웨이까지 역전파한다. 게이트웨이(여기)는 결정을 적재할 때 그 epoch를
 * <b>학습</b>(주체별 단조 증가)하고, 그 주체의 모든 캐시 키에 현재 epoch를 끼운다. 따라서 epoch가 한 번 오르면
 * 그 주체의 <b>옛 엔트리는 모두 한 번에 키-아웃</b>(다른 epoch라 더는 조회되지 않음) → 같은 세션에서 <b>재로그인
 * 없이</b> 위험 상승이 다음 결정부터 반영된다. 보조 인덱스 없이 O(1)이며, 키-아웃된 고아는 lazy/크기상한으로 회수된다.
 *
 * <p><b>위험적응 TTL:</b> 적재 TTL은 결정의 위험 점수에 따라 달라진다 — 위험이 높을수록 <b>짧게</b> 캐싱해
 * 더 자주 재평가한다({@code high-risk-score} 이상 → {@code high-risk-ttl}). 위험 변화의 능동 무효화(epoch)와
 * 별개로, 점수가 높은 결정이 오래 굳지 않게 하는 시간 기반 안전망이다.
 *
 * <p><b>왜 직접 구현(외부 캐시 라이브러리 미사용):</b> 부하 데모의 캐시는 핫 키 소수에 대한 짧은 TTL이면
 * 충분하고, TTL·무효화·크기상한을 코드에 그대로 드러내 "캐싱의 효과와 위험"을 보이는 게 학습 목적에 맞다.
 * 만료는 조회 시 lazy로 걷어내고, 크기상한을 둬 무한 증식을 막는다(데모 기준 단순화 — 정교한 LRU는 미구현).
 *
 * <p><b>안전:</b> 적재는 PDP가 <i>실제로 내린</i> 결정(ALLOW/정책 DENY)만 대상으로 한다. PDP 호출 실패로 인한
 * fail-close(DENY)는 호출부에서 처리되어 캐시에 들어오지 않으므로, 일시적 장애가 캐시에 굳어버리지 않는다.
 *
 * <p>설정: {@code ztg.gateway.decision-cache.{enabled,ttl,high-risk-ttl,high-risk-score,max-size}}.
 * {@code enabled=false}로 캐싱을 꺼 <b>같은 바이너리로 before(캐시 off)/after(캐시 on)</b> 부하를 비교할 수 있다.
 */
@Component
class DecisionCache {

    /** 캐시 키: 정규화 요청(레이트 제외) + 그 주체의 현재 epoch. epoch가 다르면 다른 키 = 옛 결정 키-아웃. */
    private record Key(DecisionRequest request, long epoch) {}

    /** 캐시 항목: 결정 + 만료 시각(nanoTime 기준). */
    private record Entry(DecisionResponse response, long expiresAtNanos) {}

    private final ConcurrentHashMap<Key, Entry> store = new ConcurrentHashMap<>();
    /** 주체별 게이트웨이가 학습한 현재 epoch(능동 무효화 토큰). 단조 증가 — 더 큰 값만 채택. */
    private final ConcurrentHashMap<String, Long> knownEpochs = new ConcurrentHashMap<>();
    private final boolean enabled;
    private final long ttlNanos;
    private final long highRiskTtlNanos;
    private final int highRiskScore;
    private final int maxSize;
    private final LongSupplier nanoClock;
    private final Counter hits;
    private final Counter misses;

    DecisionCache(@Value("${ztg.gateway.decision-cache.enabled:true}") boolean enabled,
                  @Value("${ztg.gateway.decision-cache.ttl:5s}") Duration ttl,
                  @Value("${ztg.gateway.decision-cache.high-risk-ttl:1s}") Duration highRiskTtl,
                  @Value("${ztg.gateway.decision-cache.high-risk-score:50}") int highRiskScore,
                  @Value("${ztg.gateway.decision-cache.max-size:10000}") int maxSize,
                  MeterRegistry meterRegistry) {
        this(enabled, ttl, highRiskTtl, highRiskScore, maxSize, meterRegistry, System::nanoTime);
    }

    /** 테스트용 — 단조 시계를 주입해 위험적응 TTL 만료를 결정적으로 검증한다. */
    DecisionCache(boolean enabled, Duration ttl, Duration highRiskTtl, int highRiskScore, int maxSize,
                  MeterRegistry meterRegistry, LongSupplier nanoClock) {
        this.enabled = enabled;
        this.ttlNanos = ttl.toNanos();
        this.highRiskTtlNanos = highRiskTtl.toNanos();
        this.highRiskScore = highRiskScore;
        this.maxSize = maxSize;
        this.nanoClock = nanoClock;
        // 캐시 히트율을 보이는 RED 보조 지표(히트면 PDP 호출이 통째로 빠진다).
        this.hits = meterRegistry.counter("ztg.pdp.cache", "result", "hit");
        this.misses = meterRegistry.counter("ztg.pdp.cache", "result", "miss");
        meterRegistry.gauge("ztg.pdp.cache.size", store, java.util.Map::size);
    }

    /** 살아 있는(미만료) 결정이 있으면 반환, 없으면 {@code null}. 캐시가 꺼져 있으면 항상 {@code null}(지표 미집계). */
    DecisionResponse getIfPresent(DecisionRequest request) {
        if (!enabled) {
            return null;
        }
        Key key = cacheKey(request, knownEpochs.getOrDefault(request.subject(), 0L));
        Entry entry = store.get(key);
        // (now - expiresAt) >= 0 이면 만료. 차이로 비교해 nanoTime 래핑에도 안전하게 판정한다.
        if (entry == null || nanoClock.getAsLong() - entry.expiresAtNanos() >= 0) {
            if (entry != null) {
                store.remove(key, entry);   // 만료분 lazy 제거
            }
            misses.increment();
            return null;
        }
        hits.increment();
        return entry.response();
    }

    /**
     * 결정을 위험적응 TTL 동안 캐싱한다. 적재 전에 결정이 운반한 {@link DecisionResponse#epoch()}를 학습해
     * (주체별 단조 증가) 이후 조회의 키가 올바른 세대를 가리키게 한다 — epoch가 올랐으면 이 주체의 옛 엔트리는
     * 즉시 키-아웃된다(능동 무효화). 가득 찼고 새 키면 적재를 건너뛴다(데모 단순화).
     *
     * <p><b>경합 안전(fail-close):</b> 키는 {@code knownEpochs}를 다시 읽지 않고 <b>이 결정의 {@code value.epoch()}</b>로
     * 만든다. 위험 전이 순간 같은 주체·요청에 두 평가가 동시에 진행 중일 때, 뒤늦게 도착한 옛 epoch의 stale ALLOW가
     * 더 큰 epoch로 키잉돼 신선한 DENY를 덮어쓰는 것을 막는다 — 옛 결정은 옛 세대 키에 고립돼 조회되지 않는다.
     */
    void put(DecisionRequest request, DecisionResponse value) {
        if (!enabled) {
            return;
        }
        learnEpoch(request.subject(), value.epoch());
        Key key = cacheKey(request, value.epoch());
        if (store.size() >= maxSize && !store.containsKey(key)) {
            return;
        }
        store.put(key, new Entry(value, nanoClock.getAsLong() + ttlNanosFor(value.score())));
    }

    /** 주체의 현재 epoch를 더 큰 값으로만 갱신한다(역전파 순서 뒤바뀜·재시도에도 단조 보장). */
    private void learnEpoch(String subject, long epoch) {
        knownEpochs.merge(subject, epoch, Math::max);
    }

    /** 위험 점수가 임계 이상이면 짧은 TTL(자주 재평가), 아니면 기본 TTL. */
    private long ttlNanosFor(int score) {
        return score >= highRiskScore ? highRiskTtlNanos : ttlNanos;
    }

    /**
     * 캐시 키를 만든다 — 요청에서 <b>휘발성 레이트 신호</b>({@link RiskSignals#CTX_REQUESTS_IN_WINDOW})를
     * 걷어낸 정규화 요청에, 주어진 <b>epoch</b>를 끼운다. 레이트를 빼는 이유는 매 요청 달라져 키에 넣으면
     * 캐시가 무력화되기 때문이다(결정 #3). 나머지 맥락(source-ip·hour-of-day)은 그대로 둬 새 IP/시간대가 정상적으로
     * 다른 키가 되게 한다. epoch를 끼우는 이유는 위험 변화 시 옛 엔트리를 한 번에 키-아웃하기 위함이다(결정 #1).
     *
     * <p>epoch를 인자로 받는 이유: 조회는 주체의 <b>현재</b> 세대({@code knownEpochs})로, 적재는 <b>그 결정의</b>
     * 세대로 키잉해야 경합 시 stale 결정이 신선한 결정을 덮지 않는다({@link #put} 경합 안전 참고).
     */
    private Key cacheKey(DecisionRequest request, long epoch) {
        Map<String, String> context = request.context();
        if (context == null || !context.containsKey(RiskSignals.CTX_REQUESTS_IN_WINDOW)) {
            return new Key(request, epoch);
        }
        Map<String, String> stable = new LinkedHashMap<>(context);
        stable.remove(RiskSignals.CTX_REQUESTS_IN_WINDOW);
        return new Key(new DecisionRequest(request.subject(), request.action(), request.resource(), stable), epoch);
    }
}
