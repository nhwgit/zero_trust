package com.ztg.gateway;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 게이트웨이(PEP)가 보는 <b>주체별 요청 레이트</b>를 슬라이딩 윈도우로 센다.
 *
 * <p>게이트웨이는 캐시 히트를 포함한 <b>모든</b> 요청을 통과시키므로 레이트의 권위 있는 관측자다
 * (README 결정 #3). 주체마다 최근 {@code window} 동안의 요청 타임스탬프를 모아 두고, 새 요청이 올 때마다
 * 윈도우 밖으로 빠진 것을 걷어낸 뒤 남은 개수를 돌려준다 — 이 수가 "지금 이 주체가 얼마나 몰아치는가"의
 * 신호로 PDP→PIP까지 흘러가 위험점수에 반영된다.
 *
 * <p><b>단일 GW 가정:</b> 카운터는 인메모리다(다중 GW 합산은 roadmap step ④ Redis fan-out에서). 데모/단일
 * 노드에선 이걸로 충분하고, "레이트는 어디서 누가 세는가"를 코드에 드러내는 게 학습 목적에 맞다.
 *
 * <p><b>스레드 안전:</b> 게이트웨이는 리액티브 멀티스레드이므로 주체별 큐에 대한 갱신을 그 큐 객체로
 * 동기화한다(주체 단위 락 → 경합 국소화). 시간은 단조 증가하는 {@code nanoTime} 소스를 쓴다(벽시계 점프 무관).
 */
@Component
class SubjectRateObserver {

    /** 주체 → 최근 요청 타임스탬프(nanos) 큐. */
    private final ConcurrentHashMap<String, Deque<Long>> windows = new ConcurrentHashMap<>();
    private final long windowNanos;
    /** 단조 시계 소스(테스트에서 주입 가능). 기본은 {@link System#nanoTime()}. */
    private final LongSupplier nanoClock;

    SubjectRateObserver(@Value("${ztg.gateway.rate.window:10s}") Duration window) {
        this(window, System::nanoTime);
    }

    /** 테스트용 — 시계를 주입해 윈도우 만료를 결정적으로 검증한다. */
    SubjectRateObserver(Duration window, LongSupplier nanoClock) {
        this.windowNanos = window.toNanos();
        this.nanoClock = nanoClock;
    }

    /**
     * 이 주체의 이번 요청을 기록하고, 윈도우 안에 남은 요청 수(이번 것 포함)를 돌려준다.
     * 윈도우보다 오래된 타임스탬프는 이 호출에서 걷어낸다(lazy eviction — 별도 청소 스레드 불필요).
     */
    int record(String subject) {
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
