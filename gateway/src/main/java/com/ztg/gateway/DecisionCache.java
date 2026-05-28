package com.ztg.gateway;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 * 뺀</b> 정규화 키(값 동등성). {@code source-ip}·{@code hour-of-day}는 키에 남겨 새 IP/시간대는 자동 캐시
 * 미스 → 재평가가 되지만(전방호환), {@code requests-in-window}는 매 요청 달라져 키에 넣으면 캐시가 통째로
 * 무력화되므로 제외한다(README 결정 #3). 레이트 급증은 키 분기가 아니라 <b>능동 무효화(epoch bump, step 4)</b>로
 * 처리한다. 짧은 TTL은 정책/위험 변화의 <b>반영 지연을 바운드</b>하는 안전망이다.
 *
 * <p><b>왜 직접 구현(외부 캐시 라이브러리 미사용):</b> 부하 데모의 캐시는 핫 키 소수에 대한 짧은 TTL이면
 * 충분하고, TTL·무효화·크기상한을 코드에 그대로 드러내 "캐싱의 효과와 위험"을 보이는 게 학습 목적에 맞다.
 * 만료는 조회 시 lazy로 걷어내고, 크기상한을 둬 무한 증식을 막는다(데모 기준 단순화 — 정교한 LRU는 미구현).
 *
 * <p><b>안전:</b> 적재는 PDP가 <i>실제로 내린</i> 결정(ALLOW/정책 DENY)만 대상으로 한다. PDP 호출 실패로 인한
 * fail-close(DENY)는 호출부에서 처리되어 캐시에 들어오지 않으므로, 일시적 장애가 캐시에 굳어버리지 않는다.
 *
 * <p>설정: {@code ztg.gateway.decision-cache.{enabled,ttl,max-size}}. {@code enabled=false}로 캐싱을 꺼
 * <b>같은 바이너리로 before(캐시 off)/after(캐시 on)</b> 부하를 비교할 수 있다.
 */
@Component
class DecisionCache {

    /** 캐시 항목: 결정 + 만료 시각(nanoTime 기준). */
    private record Entry(DecisionResponse response, long expiresAtNanos) {}

    private final ConcurrentHashMap<DecisionRequest, Entry> store = new ConcurrentHashMap<>();
    private final boolean enabled;
    private final long ttlNanos;
    private final int maxSize;
    private final Counter hits;
    private final Counter misses;

    DecisionCache(@Value("${ztg.gateway.decision-cache.enabled:true}") boolean enabled,
                  @Value("${ztg.gateway.decision-cache.ttl:5s}") Duration ttl,
                  @Value("${ztg.gateway.decision-cache.max-size:10000}") int maxSize,
                  MeterRegistry meterRegistry) {
        this.enabled = enabled;
        this.ttlNanos = ttl.toNanos();
        this.maxSize = maxSize;
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
        DecisionRequest key = cacheKey(request);
        Entry entry = store.get(key);
        // (now - expiresAt) >= 0 이면 만료. 차이로 비교해 nanoTime 래핑에도 안전하게 판정한다.
        if (entry == null || System.nanoTime() - entry.expiresAtNanos() >= 0) {
            if (entry != null) {
                store.remove(key, entry);   // 만료분 lazy 제거
            }
            misses.increment();
            return null;
        }
        hits.increment();
        return entry.response();
    }

    /** 결정을 TTL 동안 캐싱한다. 가득 찼고 새 키면 적재를 건너뛴다(데모 단순화). */
    void put(DecisionRequest request, DecisionResponse value) {
        if (!enabled) {
            return;
        }
        DecisionRequest key = cacheKey(request);
        if (store.size() >= maxSize && !store.containsKey(key)) {
            return;
        }
        store.put(key, new Entry(value, System.nanoTime() + ttlNanos));
    }

    /**
     * 캐시 키를 만든다 — 요청에서 <b>휘발성 레이트 신호</b>({@link RiskSignals#CTX_REQUESTS_IN_WINDOW})만
     * 걷어낸 동등 키. 이 값은 매 요청 달라져 키에 넣으면 캐시가 무력화되기 때문이다(결정 #3). 나머지
     * 맥락(source-ip·hour-of-day)은 그대로 둬 새 IP/시간대가 정상적으로 다른 키가 되게 한다.
     * context에 레이트 키가 없으면 원본을 그대로 키로 쓴다(불필요한 복사 회피).
     */
    private static DecisionRequest cacheKey(DecisionRequest request) {
        Map<String, String> context = request.context();
        if (context == null || !context.containsKey(RiskSignals.CTX_REQUESTS_IN_WINDOW)) {
            return request;
        }
        Map<String, String> stable = new LinkedHashMap<>(context);
        stable.remove(RiskSignals.CTX_REQUESTS_IN_WINDOW);
        return new DecisionRequest(request.subject(), request.action(), request.resource(), stable);
    }
}
