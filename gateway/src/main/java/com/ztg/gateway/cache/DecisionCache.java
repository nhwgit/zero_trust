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
 * <p><b>다중 게이트웨이(Redis fan-out):</b> 위 lazy 학습은 <i>이 노드</i>가 그 주체로 PDP를 한 번 다녀와야
 * 새 epoch를 안다. 노드가 여럿이면 위험을 유발하지 않은 다른 노드는 TTL 동안 옛 ALLOW를 계속 히트로 낸다.
 * 그래서 epoch 권위자(PIP)가 epoch를 올리는 순간 Redis pub/sub으로 fan-out하고, 각 노드는
 * {@link #applyRemoteEpoch}로 즉시 학습 epoch를 끌어올려 <b>전 노드의 캐시를 동시에</b> 키-아웃한다.
 * pub/sub 유실 시에도 lazy 학습+TTL이 백스톱이라 무효화는 보장된다([[EpochFanout]]).
 *
 * <p><b>위험적응 TTL:</b> 적재 TTL은 결정의 위험 점수에 따라 달라진다 — 위험이 높을수록 <b>짧게</b> 캐싱해
 * 더 자주 재평가한다({@code high-risk-score} 이상 → {@code high-risk-ttl}). 위험 변화의 능동 무효화(epoch)와
 * 별개로, 점수가 높은 결정이 오래 굳지 않게 하는 시간 기반 안전망이다.
 *
 * <p><b>레이트 밴드 변화 → 강제 바이패스(능동 무효화의 트리거):</b> 휘발성 레이트는 키에서 빠져 있어
 * 캐시만으로는 급증을 못 잡는다 — 같은 IP에서 폭주가 시작돼도 키가 그대로라 옛 ALLOW가 계속 히트한다.
 * 그래서 조회 시 이 주체의 레이트가 <b>밴드(임계 {@code burst-threshold} 초과 여부)를 넘나들면</b>(직전 관측 대비
 * 전이) 그 한 요청을 <b>강제 미스</b>로 만들어 PDP 재평가를 유발한다. 그 재평가가 폭주 신호를 PIP까지 실어
 * 보내 점수↑→epoch bump→옛 엔트리 키-아웃으로 이어진다 — <b>이것이 같은 IP 급증을 능동 무효화로 잇는 트리거</b>다.
 * <b>엣지 트리거</b>(밴드가 바뀐 순간만)라 폭주가 지속되는 동안엔 다시 캐시가 동작한다(레벨 트리거였다면 폭주
 * 내내 캐시가 죽어 부하 데모가 무너진다). 새 IP는 이 경로가 필요 없다 — 키에 IP가 남아 자동 미스→재평가다.
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
    /** 주체별 직전 레이트 밴드(true=폭주). 밴드가 바뀌는 순간만 강제 바이패스(엣지 트리거). */
    private final ConcurrentHashMap<String, Boolean> lastBand = new ConcurrentHashMap<>();
    private final boolean enabled;
    private final long ttlNanos;
    private final long highRiskTtlNanos;
    private final int highRiskScore;
    private final int burstThreshold;
    private final int maxSize;
    private final LongSupplier nanoClock;
    private final Counter hits;
    private final Counter misses;
    private final Counter bypasses;
    private final Counter fanoutApplied;

    DecisionCache(@Value("${ztg.gateway.decision-cache.enabled:true}") boolean enabled,
                  @Value("${ztg.gateway.decision-cache.ttl:5s}") Duration ttl,
                  @Value("${ztg.gateway.decision-cache.high-risk-ttl:1s}") Duration highRiskTtl,
                  @Value("${ztg.gateway.decision-cache.high-risk-score:50}") int highRiskScore,
                  @Value("${ztg.gateway.rate.burst-threshold:60}") int burstThreshold,
                  @Value("${ztg.gateway.decision-cache.max-size:10000}") int maxSize,
                  MeterRegistry meterRegistry) {
        this(enabled, ttl, highRiskTtl, highRiskScore, burstThreshold, maxSize, meterRegistry, System::nanoTime);
    }

    /** 테스트용 — 단조 시계를 주입해 위험적응 TTL 만료를 결정적으로 검증한다. */
    DecisionCache(boolean enabled, Duration ttl, Duration highRiskTtl, int highRiskScore, int burstThreshold,
                  int maxSize, MeterRegistry meterRegistry, LongSupplier nanoClock) {
        this.enabled = enabled;
        this.ttlNanos = ttl.toNanos();
        this.highRiskTtlNanos = highRiskTtl.toNanos();
        this.highRiskScore = highRiskScore;
        this.burstThreshold = burstThreshold;
        this.maxSize = maxSize;
        this.nanoClock = nanoClock;
        // 캐시 히트율을 보이는 RED 보조 지표(히트면 PDP 호출이 통째로 빠진다).
        this.hits = meterRegistry.counter("ztg.pdp.cache", "result", "hit");
        this.misses = meterRegistry.counter("ztg.pdp.cache", "result", "miss");
        // 레이트 밴드 변화로 인한 강제 재평가(능동 무효화 트리거). 콜드 미스와 구분해 따로 센다.
        this.bypasses = meterRegistry.counter("ztg.pdp.cache", "result", "bypass");
        // 다른 GW가 유발한 epoch 상승을 Redis fan-out으로 받아 적용한 횟수(원격 무효화 가시성).
        this.fanoutApplied = meterRegistry.counter("ztg.pdp.cache", "result", "fanout");
        meterRegistry.gauge("ztg.pdp.cache.size", store, java.util.Map::size);
    }

    /** 살아 있는(미만료) 결정이 있으면 반환, 없으면 {@code null}. 캐시가 꺼져 있으면 항상 {@code null}(지표 미집계). */
    DecisionResponse getIfPresent(DecisionRequest request) {
        if (!enabled) {
            return null;
        }
        // 레이트 밴드가 직전 관측과 달라졌으면(임계 넘나듦) 이 요청만 강제 미스로 만들어 재평가를 유발한다.
        // 휘발성 레이트는 키에서 빠져 캐시가 급증을 못 잡으므로, 급증을 능동 무효화(epoch)로 잇는 트리거다.
        if (rateBandChanged(request)) {
            bypasses.increment();
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

    /**
     * <b>다른 게이트웨이가 유발한</b> epoch 상승을 Redis fan-out으로 받아 적용한다(다중 GW 능동 무효화).
     * 이 노드가 그 주체의 PDP 왕복을 아직 안 했어도, 학습된 epoch가 즉시 올라 그 주체의 옛 엔트리가
     * 한 번에 키-아웃된다 → 위험을 유발하지 않은 노드도 <b>재로그인 없이</b> 다음 요청부터 재평가한다.
     *
     * <p>{@link #learnEpoch}와 같은 단조(max) 학습이라 옛/중복 메시지는 무시된다(부활 없음). 실제로
     * epoch가 전진했을 때만 지표를 올려, lazy 학습으로 이미 알던 값의 재수신과 구분한다.
     */
    void applyRemoteEpoch(String subject, long epoch) {
        long prior = knownEpochs.getOrDefault(subject, 0L);
        learnEpoch(subject, epoch);
        if (epoch > prior) {
            fanoutApplied.increment();
        }
    }

    /** 위험 점수가 임계 이상이면 짧은 TTL(자주 재평가), 아니면 기본 TTL. */
    private long ttlNanosFor(int score) {
        return score >= highRiskScore ? highRiskTtlNanos : ttlNanos;
    }

    /**
     * 이 주체의 레이트 밴드(폭주 여부 = {@code requests-in-window > burst-threshold})가 직전 관측 대비
     * <b>전이</b>했는지 본다. 전이면 {@code true}(→ 호출부가 강제 미스 처리). 관측할 때마다 현재 밴드를 기록하고
     * 직전 밴드를 회수해 비교하므로 <b>엣지 트리거</b>다 — 밴드가 유지되는 동안엔 전이가 아니라 캐시가 정상 동작한다.
     *
     * <p>첫 관측(직전 밴드 없음)은 전이로 보지 않는다(기준만 세움). 레이트 신호가 없거나 숫자가 아니면 비교를
     * 건너뛴다(부재는 트리거 아님). 레이트 자체는 캐시 키에서 제외돼 있어(결정 #3) 이 비교만이 급증을 캐시에 알린다.
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
        boolean burst;
        try {
            burst = Integer.parseInt(raw.trim()) > burstThreshold;
        } catch (NumberFormatException e) {
            return false;   // 해석 불가한 레이트는 트리거로 쓰지 않는다(보수적)
        }
        Boolean prior = lastBand.put(request.subject(), burst);   // 기록하며 직전 밴드 회수(주체별)
        return prior != null && prior != burst;                   // 첫 관측은 전이 아님
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
