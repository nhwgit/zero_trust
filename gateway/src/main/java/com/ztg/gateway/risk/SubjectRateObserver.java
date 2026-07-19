package com.ztg.gateway.risk;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.ztg.gateway.config.RateProperties;

import reactor.core.publisher.Mono;

/**
 * 주체별 요청 레이트를 노드-로컬 슬라이딩 윈도우로 세는 기본 관측자. 다중 GW 모드에선
 * {@link RedisRateObserver}가 소유권을 가져가고 이 카운터는 warm standby 폴백으로 남는다.
 * 주체별 큐를 그 큐 객체로 동기화하고(주체 단위 락), 시간은 단조 {@code nanoTime} 소스를 쓴다(벽시계 점프 무관).
 */
@Component
public class SubjectRateObserver implements RateObserver {

    private final ConcurrentHashMap<String, Deque<Long>> windows = new ConcurrentHashMap<>();
    private final long windowNanos;
    private final LongSupplier nanoClock;

    @Autowired
    public SubjectRateObserver(RateProperties rate) {
        this(rate.window(), System::nanoTime);
    }

    /** 테스트용 — 시계를 주입해 윈도우 만료를 결정적으로 검증한다. */
    SubjectRateObserver(Duration window, LongSupplier nanoClock) {
        this.windowNanos = window.toNanos();
        this.nanoClock = nanoClock;
    }

    @Override
    public Mono<Integer> observe(String subject) {
        return Mono.fromSupplier(() -> record(subject));
    }

    /**
     * 이번 요청을 기록하고, 윈도우 안에 남은 요청 수(이번 것 포함)를 돌려준다.
     * 동기 int 반환 — {@link RedisRateObserver}가 폴백 경로에서 직접 쓴다.
     */
    public int record(String subject) {
        long now = nanoClock.getAsLong();
        long cutoff = now - windowNanos;
        Deque<Long> q = windows.computeIfAbsent(subject, k -> new ArrayDeque<>());
        synchronized (q) {
            q.addLast(now);
            // (ts - cutoff) < 0 이면 윈도우 밖 — 차이로 비교해 nanoTime 래핑에도 안전하게 판정한다.
            while (!q.isEmpty() && q.peekFirst() - cutoff < 0) {
                q.pollFirst();
            }
            return q.size();
        }
    }
}
