package com.ztg.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/**
 * {@link SubjectRateObserver} 단위 테스트 — 슬라이딩 윈도우 누적/만료/주체 격리를 주입 시계로 결정적으로 검증한다.
 */
class SubjectRateObserverTest {

    /** 테스트가 직접 진군시키는 가짜 나노 시계. */
    private final AtomicLong now = new AtomicLong(0);

    private SubjectRateObserver observer(Duration window) {
        return new SubjectRateObserver(window, now::get);
    }

    @Test
    void countsAccumulateWithinWindow() {
        SubjectRateObserver observer = observer(Duration.ofSeconds(10));
        assertThat(observer.record("alice")).isEqualTo(1);
        assertThat(observer.record("alice")).isEqualTo(2);
        assertThat(observer.record("alice")).isEqualTo(3);
    }

    @Test
    void timestampsOlderThanWindowAreEvicted() {
        SubjectRateObserver observer = observer(Duration.ofSeconds(10));
        observer.record("alice");                       // t=0
        now.set(Duration.ofSeconds(5).toNanos());
        observer.record("alice");                       // t=5  → 윈도우 안 2건
        now.set(Duration.ofSeconds(11).toNanos());
        // t=11: t=0은 윈도우(11-10=1) 밖으로 밀려나고 t=5와 지금 것만 남는다.
        assertThat(observer.record("alice")).isEqualTo(2);
    }

    @Test
    void subjectsAreCountedIndependently() {
        SubjectRateObserver observer = observer(Duration.ofSeconds(10));
        observer.record("alice");
        observer.record("alice");
        assertThat(observer.record("bob")).isEqualTo(1);   // bob은 alice 카운트에 영향받지 않는다
        assertThat(observer.record("alice")).isEqualTo(3);
    }
}
