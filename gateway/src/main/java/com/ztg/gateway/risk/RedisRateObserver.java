package com.ztg.gateway.risk;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import com.ztg.gateway.config.RateProperties;

import reactor.core.publisher.Mono;

/**
 * 다중 GW 모드의 레이트 관측 소유자 — 주체별 슬라이딩 윈도우를 Redis 공유 집계로 센다
 * (노드-로컬 카운터의 1/N 희석 방지). 요청당 Lua 스크립트 1회 왕복이며, 점수(score)는 노드 시계가
 * 아니라 Redis 서버 {@code TIME}이라 노드 간 벽시계 편차가 윈도우 판정에 섞이지 않는다.
 *
 * <p>Redis 불통 시 전면 차단이 아니라 노드-로컬 카운터로 강등한다(fail-degraded — 레이트는 보조
 * 신호일 뿐). 로컬 카운터는 평상시에도 항상 함께 적셔 두므로(warm standby) 강등 순간 빈 윈도우에서
 * 시작하지 않고, 한 요청은 어느 경로로든 정확히 한 번만 세어진다.
 */
public class RedisRateObserver implements RateObserver {

    static final String KEY_PREFIX = "ztg:rate:";

    /**
     * 슬라이딩 윈도우 원자 갱신: 윈도우 밖 제거 → 이번 요청 기록 → 키 TTL 갱신 → 남은 수 반환.
     * ARGV[1]=윈도우(ms), ARGV[2]=유니크 멤버(같은 ms의 요청끼리 덮어쓰지 않게).
     */
    private static final RedisScript<Long> SLIDING_WINDOW = RedisScript.of("""
            local windowMs = tonumber(ARGV[1])
            local t = redis.call('TIME')
            local nowMs = t[1] * 1000 + math.floor(t[2] / 1000)
            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', nowMs - windowMs)
            redis.call('ZADD', KEYS[1], nowMs, ARGV[2])
            redis.call('PEXPIRE', KEYS[1], windowMs)
            return redis.call('ZCARD', KEYS[1])
            """, Long.class);

    private static final Logger log = LoggerFactory.getLogger(RedisRateObserver.class);

    private final ReactiveStringRedisTemplate redis;
    private final SubjectRateObserver localFallback;
    private final String windowMillis;
    /** 강등/복구 전이 순간에만 로그를 내기 위한 상태 기억. */
    private final AtomicBoolean degraded = new AtomicBoolean(false);
    private final Counter sharedObservations;
    private final Counter fallbackObservations;

    public RedisRateObserver(ReactiveStringRedisTemplate redis, SubjectRateObserver localFallback,
                             RateProperties rate, MeterRegistry meterRegistry) {
        this.redis = redis;
        this.localFallback = localFallback;
        this.windowMillis = Long.toString(rate.window().toMillis());
        // fallback 카운트가 이어지면 공유 집계가 죽어 희석 문제로 퇴행 중이라는 신호다.
        this.sharedObservations = meterRegistry.counter("ztg.rate.observe", "source", "shared");
        this.fallbackObservations = meterRegistry.counter("ztg.rate.observe", "source", "fallback");
    }

    @Override
    public Mono<Integer> observe(String subject) {
        // 로컬 카운터를 항상 함께 적신다(warm standby) — 폴백이 빈 윈도우에서 시작하지 않는다.
        return Mono.fromSupplier(() -> localFallback.record(subject))
                .flatMap(localCount -> redis.execute(SLIDING_WINDOW,
                                List.of(KEY_PREFIX + subject),
                                List.of(windowMillis, UUID.randomUUID().toString()))
                        .single()
                        .map(Long::intValue)
                        .doOnNext(shared -> {
                            sharedObservations.increment();
                            if (degraded.compareAndSet(true, false)) {
                                log.info("shared rate observation recovered (redis reachable again)");
                            }
                        })
                        .onErrorResume(e -> {
                            fallbackObservations.increment();
                            if (degraded.compareAndSet(false, true)) {
                                log.warn("shared rate observation degraded to node-local fallback: {}", e.toString());
                            }
                            return Mono.just(localCount);
                        }));
    }
}
