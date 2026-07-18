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
 * 다중 GW 모드의 레이트 관측 소유자 — 주체별 슬라이딩 윈도우를 <b>Redis 공유 집계</b>로 센다.
 *
 * <p><b>왜 공유 집계인가:</b> 노드-로컬 카운터는 GW N대에서 폭주를 1/N로 희석해 전역 폭주를 아무
 * 노드도 못 잡고, 노드마다 다른 카운트가 PIP 밴드 상태(주체당 1개)에 섞여 플립-플롭을 만든다
 * ({@link RateObserver} 참조). 전 노드가 같은 키를 갱신·조회하면 카운트가 전역이 되어 두 증상이
 * 근원에서 사라진다 — 임계({@code burst-threshold})의 의미도 "전역 레이트 기준"으로 복원된다.
 *
 * <p><b>비용과 경계:</b> 요청당 Lua 스크립트 <b>1회 왕복</b>(ZREMRANGEBYSCORE+ZADD+PEXPIRE+ZCARD를
 * 원자로 묶음)이다. fan-out 모드에서만 쓰이므로 단일 GW/테스트의 핫패스는 그대로 인메모리다. 호출은
 * 리액티브(비차단)이고, 지연 상한은 기존 Redis 커맨드 타임아웃({@code spring.data.redis.timeout})이
 * 그대로 바운드한다(새 노브 없음). 저장은 윈도우 길이 TTL의 휘발 zset이라 영속/AOF가 필요 없다
 * — fan-out과 같은 Redis를 그대로 재사용한다(관리포인트 불증).
 *
 * <p><b>시계:</b> 점수(score)는 노드 시계가 아니라 스크립트 안의 Redis 서버 {@code TIME}이다 —
 * 노드 간 벽시계 편차가 윈도우 판정에 섞이지 않는다(단일 시계 = 단일 진실).
 *
 * <p><b>장애 시 fail-degraded(전면 차단 아님):</b> 레이트는 보조 위험신호이지 인가 그 자체가 아니다.
 * Redis 불통이 전 요청 차단(fail-close)이 되면 관측 보조계가 가용성을 역전시키므로, 실패 시
 * <b>노드-로컬 카운터로 강등</b>한다(= 기존 단일 GW 동작). 로컬 카운터는 평상시에도 항상 함께
 * 적셔 두므로(warm standby) 강등 순간 빈 윈도우에서 시작하지 않고, 한 요청은 어느 경로로든
 * <b>정확히 한 번</b>만 세어진다. 강등/복구는 상태 전이 시에만 로그를 남긴다(요청당 로그 폭풍 방지).
 */
public class RedisRateObserver implements RateObserver {

    /** 주체별 공유 카운터의 키 접두어. 값은 (요청 시각 ms, 유니크 멤버)의 zset. */
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
    /** 현재 강등 상태(true=로컬 폴백 중). 전이 순간에만 로그를 내기 위한 상태 기억. */
    private final AtomicBoolean degraded = new AtomicBoolean(false);
    private final Counter sharedObservations;
    private final Counter fallbackObservations;

    public RedisRateObserver(ReactiveStringRedisTemplate redis, SubjectRateObserver localFallback,
                             RateProperties rate, MeterRegistry meterRegistry) {
        this.redis = redis;
        this.localFallback = localFallback;
        this.windowMillis = Long.toString(rate.window().toMillis());
        // 관측 소유권의 실측 가시성: fallback이 이어지면 공유 집계가 죽어 희석 문제로 퇴행 중이라는 신호다.
        this.sharedObservations = meterRegistry.counter("ztg.rate.observe", "source", "shared");
        this.fallbackObservations = meterRegistry.counter("ztg.rate.observe", "source", "fallback");
    }

    @Override
    public Mono<Integer> observe(String subject) {
        // 로컬 카운터를 항상 함께 적신다(warm standby) — Redis 장애 순간 폴백이 빈 윈도우에서 시작하지
        // 않는다. 이 요청은 (공유 성공이든 폴백이든) 결과에 정확히 한 번만 반영된다.
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
