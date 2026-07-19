package com.ztg.gateway.cache;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.ztg.gateway.config.DecisionCacheProperties;
import com.ztg.gateway.config.RateProperties;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.risk.BurstBandPolicy;

/**
 * PEP의 인가 결정 캐시 — 키는 "정규화 요청(휘발성 레이트 제외) + 주체 epoch".
 *
 * <p>핵심 메커니즘: ① epoch(주체별 단조 세대 토큰)가 오르면 옛 엔트리가 한 번에 키-아웃되는
 * <b>능동 무효화</b>(로컬 학습 + Redis fan-out 수신), ② 위험 점수가 높을수록 짧은 <b>위험적응 TTL</b>,
 * ③ 레이트 밴드 전이 순간의 <b>강제 바이패스</b>(엣지 트리거)로 급증을 재평가로 잇기,
 * ④ 가득 참 시 만료 고아 <b>sweep</b>(IP 회전으로 캐시를 영구 off시키는 공격 차단).
 */
@Component
public class DecisionCache {

    private record Key(DecisionRequest request, long epoch) {}

    private record Entry(DecisionResponse response, long expiresAtNanos) {}

    private final ConcurrentHashMap<Key, Entry> store = new ConcurrentHashMap<>();
    /** 주체별 학습된 현재 epoch. 단조 증가 — 더 큰 값만 채택. */
    private final ConcurrentHashMap<String, Long> knownEpochs = new ConcurrentHashMap<>();
    /** 주체별 직전 레이트 밴드(true=폭주). 전이 순간만 바이패스하는 엣지 트리거의 비교 기준. */
    private final ConcurrentHashMap<String, Boolean> lastBand = new ConcurrentHashMap<>();
    private final boolean enabled;
    private final long ttlNanos;
    private final long highRiskTtlNanos;
    private final int highRiskScore;
    private final BurstBandPolicy burstBandPolicy;
    private final int maxSize;
    private final long sweepIntervalNanos;
    /** 다음 sweep 허용 시각. CAS로 선점해 한 시점에 한 스레드만 스캔한다. */
    private final AtomicLong nextSweepAtNanos;
    private final LongSupplier nanoClock;
    private final Counter hits;
    private final Counter misses;
    private final Counter bypasses;
    private final Counter fanoutApplied;
    private final Counter sweepReclaimed;

    @Autowired
    DecisionCache(DecisionCacheProperties props, RateProperties rate, MeterRegistry meterRegistry) {
        this(props, rate, meterRegistry, System::nanoTime);
    }

    /** 테스트용 — 단조 시계 주입으로 TTL 만료를 결정적으로 검증한다. */
    DecisionCache(DecisionCacheProperties props, RateProperties rate, MeterRegistry meterRegistry,
                  LongSupplier nanoClock) {
        this.enabled = props.enabled();
        this.ttlNanos = props.ttl().toNanos();
        this.highRiskTtlNanos = props.highRiskTtl().toNanos();
        this.highRiskScore = props.highRiskScore();
        // PIP rate-burst 판정과 같은 구현(BurstBandPolicy) — 두 곳의 임계 판정이 어긋나면 빈 재평가가 생긴다.
        this.burstBandPolicy = new BurstBandPolicy(rate.burstThreshold(), rate.burstExitThreshold());
        this.maxSize = props.maxSize();
        this.sweepIntervalNanos = props.sweepInterval().toNanos();
        this.nanoClock = nanoClock;
        this.nextSweepAtNanos = new AtomicLong(nanoClock.getAsLong());
        this.hits = meterRegistry.counter("ztg.pdp.cache", "result", "hit");
        this.misses = meterRegistry.counter("ztg.pdp.cache", "result", "miss");
        this.bypasses = meterRegistry.counter("ztg.pdp.cache", "result", "bypass");
        this.fanoutApplied = meterRegistry.counter("ztg.pdp.cache", "result", "fanout");
        this.sweepReclaimed = meterRegistry.counter("ztg.pdp.cache.sweep.reclaimed");
        meterRegistry.gauge("ztg.pdp.cache.size", store, Map::size);
    }

    /** 살아 있는 결정이 있으면 반환, 없으면 {@code null}. 캐시 off면 항상 {@code null}(지표 미집계). */
    public DecisionResponse getIfPresent(DecisionRequest request) {
        if (!enabled) {
            return null;
        }
        // 레이트는 키에서 빠져 있어 캐시가 급증을 못 본다 — 밴드 전이 순간만 강제 미스로 재평가를 유발한다.
        if (rateBandChanged(request)) {
            bypasses.increment();
            return null;
        }
        Key key = cacheKey(request, knownEpochs.getOrDefault(request.subject(), 0L));
        Entry entry = store.get(key);
        // 차이로 비교해 nanoTime 래핑에 안전.
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
     * 결정을 위험적응 TTL 동안 캐싱한다. 적재 전에 결정이 운반한 epoch를 학습해 옛 엔트리를 키-아웃한다.
     * 가득 찼고 새 키면 만료 고아를 sweep으로 회수하고, 그래도 가득이면 적재를 건너뛴다.
     *
     * <p>키는 {@code knownEpochs}가 아니라 <b>이 결정의</b> epoch로 만든다 — 위험 전이 순간 동시 평가 경합에서
     * 뒤늦은 옛 epoch의 stale ALLOW가 신선한 DENY를 덮지 않게(옛 결정은 옛 세대 키에 고립된다).
     */
    public void put(DecisionRequest request, DecisionResponse value) {
        if (!enabled) {
            return;
        }
        learnEpoch(request.subject(), value.epoch());
        Key key = cacheKey(request, value.epoch());
        if (store.size() >= maxSize && !store.containsKey(key)) {
            sweepExpired();
            if (store.size() >= maxSize) {
                return;
            }
        }
        store.put(key, new Entry(value, nanoClock.getAsLong() + ttlNanosFor(value.score())));
    }

    /**
     * 만료 엔트리 전수 회수. epoch 키-아웃·IP 회전으로 생긴 고아는 같은 키로 재조회되지 않아 lazy 제거에
     * 안 걸린다 — 가득 참을 만난 put이 이걸 불러 자리를 되찾고, 적재 거부는 최대 TTL로 바운드된다.
     * O(n) 스캔이라 최소 간격으로 스로틀(헛스캔 유발 2차 CPU 소모 방지), CAS 선점에 진 스레드는 지나간다.
     */
    private void sweepExpired() {
        long now = nanoClock.getAsLong();
        long allowedAt = nextSweepAtNanos.get();
        if (now - allowedAt < 0 || !nextSweepAtNanos.compareAndSet(allowedAt, now + sweepIntervalNanos)) {
            return;
        }
        int reclaimed = 0;
        for (Map.Entry<Key, Entry> e : store.entrySet()) {
            // remove(key, value)로 값까지 맞춰 지워, 스캔 중 같은 키에 새로 적재된 엔트리를 오삭하지 않는다.
            if (now - e.getValue().expiresAtNanos() >= 0 && store.remove(e.getKey(), e.getValue())) {
                reclaimed++;
            }
        }
        if (reclaimed > 0) {
            sweepReclaimed.increment(reclaimed);
        }
    }

    private void learnEpoch(String subject, long epoch) {
        knownEpochs.merge(subject, epoch, Math::max);
    }

    /**
     * 다른 게이트웨이가 유발한 epoch 상승을 Redis fan-out으로 받아 즉시 학습한다 — 이 노드가 PDP 왕복
     * 없이도 옛 엔트리가 키-아웃된다. 단조(max) 학습이라 옛/중복 메시지는 무시(부활 없음).
     */
    public void applyRemoteEpoch(String subject, long epoch) {
        long prior = knownEpochs.getOrDefault(subject, 0L);
        learnEpoch(subject, epoch);
        if (epoch > prior) {
            fanoutApplied.increment();
        }
    }

    private long ttlNanosFor(int score) {
        return score >= highRiskScore ? highRiskTtlNanos : ttlNanos;
    }

    /**
     * 레이트 밴드(폭주 여부)가 직전 관측 대비 전이했는가 — 전이면 호출부가 강제 미스 처리(엣지 트리거:
     * 밴드 유지 중엔 캐시가 정상 동작한다). 판정은 히스테리시스(이중 임계) — 경계 진동이 매번 전이로
     * 판정돼 바이패스 폭풍이 되는 것을 막는다. 첫 관측·신호 부재는 전이 아님.
     */
    private boolean rateBandChanged(DecisionRequest request) {
        Map<String, String> context = request.context();
        if (context == null) {
            return false;
        }
        String raw = context.get(RiskSignals.CTX_REQUESTS_IN_WINDOW);
        if (raw == null) {
            return false;
        }
        int requests;
        try {
            requests = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return false;
        }
        Boolean prior = lastBand.get(request.subject());
        boolean burst = burstBandPolicy.judge(requests, prior);
        lastBand.put(request.subject(), burst);
        return prior != null && prior != burst;
    }

    /**
     * 캐시 키 — 휘발성 레이트({@code requests-in-window})만 걷어낸 정규화 요청 + epoch.
     * 레이트는 매 요청 달라 키에 넣으면 캐시가 무력화되고, source-ip·hour-of-day는 남겨
     * 새 IP/시간대가 자동 미스가 되게 한다.
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
