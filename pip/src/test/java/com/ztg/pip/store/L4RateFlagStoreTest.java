package com.ztg.pip.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/**
 * L4 플래그 보류(hold) 만료 검증(L2) — 플래그는 hold 동안만 가중 근거가 되고, 지나면 자동 소멸한다
 * (가역성: 커널 신호로 오른 위험이 영구 낙인이 되지 않는다). 시계 주입으로 만료를 결정적으로 확인한다.
 */
class L4RateFlagStoreTest {

    private final AtomicLong nanos = new AtomicLong(0);
    private final L4RateFlagStore store = new L4RateFlagStore(Duration.ofSeconds(30), nanos::get);

    @Test
    void flag_is_active_within_hold_and_expires_after() {
        store.flag("1.1.1.1", 87, 5);

        L4RateFlagStore.Flag active = store.activeFlag("1.1.1.1");
        assertThat(active).isNotNull();
        assertThat(active.synsInWindow()).isEqualTo(87);

        nanos.set(Duration.ofSeconds(30).toNanos());   // 정확히 hold 경과 = 만료(경계 포함)
        assertThat(store.activeFlag("1.1.1.1")).isNull();
    }

    @Test
    void reflag_extends_hold_and_refreshes_evidence() {
        store.flag("1.1.1.1", 87, 5);
        nanos.set(Duration.ofSeconds(20).toNanos());
        store.flag("1.1.1.1", 120, 5);                 // 폭주 지속 → 재보고가 만료를 미루고 근거를 갱신

        nanos.set(Duration.ofSeconds(40).toNanos());   // 최초 기준으론 만료지만 재보고 기준으론 유효
        L4RateFlagStore.Flag active = store.activeFlag("1.1.1.1");
        assertThat(active).isNotNull();
        assertThat(active.synsInWindow()).isEqualTo(120);
    }

    @Test
    void hold_seconds_exposes_configured_hold_for_enforcement_ttl() {
        assertThat(store.holdSeconds()).isEqualTo(30L);   // 에지 차단 TTL(D3 Step 3)이 이 값과 동기화된다
    }

    @Test
    void unknown_or_null_ip_is_not_flagged() {
        assertThat(store.activeFlag("9.9.9.9")).isNull();
        assertThat(store.activeFlag(null)).isNull();
    }
}
