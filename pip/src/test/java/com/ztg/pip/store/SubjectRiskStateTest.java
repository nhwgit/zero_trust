package com.ztg.pip.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * 주체 위험 상태(직전 IP + IP 변화 hold + epoch) 검증 — 기록/조회/리셋, 미상 IP 무시, 점수 변화 시 epoch bump,
 * hold의 시작/연장/만료(가짜 단조 시계로 결정적).
 */
class SubjectRiskStateTest {

    private static final Duration HOLD = Duration.ofSeconds(30);

    private long nowNanos = 0;
    private final SubjectRiskState state = new SubjectRiskState(HOLD, () -> nowNanos);

    private void advance(Duration d) {
        nowNanos += d.toNanos();
    }

    @Test
    void records_and_reads_last_seen_ip() {
        assertThat(state.lastSeenIp("alice")).isNull();   // 첫 관측 전
        state.recordIp("alice", "1.2.3.4");
        assertThat(state.lastSeenIp("alice")).isEqualTo("1.2.3.4");
    }

    @Test
    void first_score_sets_baseline_without_bumping_epoch() {
        assertThat(state.currentEpoch("alice")).isZero();           // 관측 전 epoch 0
        assertThat(state.recordScore("alice", 10)).isZero();        // 첫 점수는 기준 설정, bump 없음
        assertThat(state.currentEpoch("alice")).isZero();
    }

    @Test
    void unchanged_score_keeps_epoch_changed_score_bumps_it() {
        state.recordScore("alice", 10);
        assertThat(state.recordScore("alice", 10)).isZero();        // 동일 점수: 안정 → 유지
        assertThat(state.recordScore("alice", 80)).isEqualTo(1L);   // 위험 상승: 능동 무효화 bump
        assertThat(state.recordScore("alice", 80)).isEqualTo(1L);   // 다시 동일: 유지
        assertThat(state.recordScore("alice", 10)).isEqualTo(2L);   // 위험 하강도 변화 → bump
    }

    @Test
    void epoch_bump_preserves_last_seen_ip() {
        state.recordScore("alice", 10);
        state.recordIp("alice", "1.2.3.4");
        state.recordScore("alice", 80);                              // bump
        assertThat(state.lastSeenIp("alice")).isEqualTo("1.2.3.4");  // IP 기준은 유지된다
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
    }

    @Test
    void first_ip_observation_does_not_start_hold() {
        state.recordIp("alice", "1.2.3.4");                          // 첫 관측 = 변화 아님
        assertThat(state.ipChangeHeld("alice")).isFalse();
    }

    @Test
    void same_ip_does_not_start_hold() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "1.2.3.4");
        assertThat(state.ipChangeHeld("alice")).isFalse();
    }

    @Test
    void ip_change_holds_until_window_elapses() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // 변화 → hold 시작
        assertThat(state.ipChangeHeld("alice")).isTrue();

        advance(HOLD.minusSeconds(1));
        assertThat(state.ipChangeHeld("alice")).isTrue();            // 창 안: 유지

        advance(Duration.ofSeconds(1));
        assertThat(state.ipChangeHeld("alice")).isFalse();           // 창 경과: 자동 해제(가역성)
    }

    @Test
    void repeated_change_extends_hold() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // t=0 변화
        advance(Duration.ofSeconds(20));
        state.recordIp("alice", "8.8.8.8");                          // t=20s 재변화 → 만료 연장(회전 = 지속 신호)
        advance(Duration.ofSeconds(20));
        assertThat(state.ipChangeHeld("alice")).isTrue();            // t=40s: 첫 hold(≤30s)는 지났지만 연장으로 유지

        advance(Duration.ofSeconds(10));
        assertThat(state.ipChangeHeld("alice")).isFalse();           // t=50s: 연장분도 만료
    }

    @Test
    void same_ip_after_change_keeps_hold_running() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // 변화 → hold 시작
        advance(Duration.ofSeconds(10));
        state.recordIp("alice", "9.9.9.9");                          // 동일 IP 관측은 hold를 끊지도 늘리지도 않음
        advance(HOLD.minusSeconds(10));
        assertThat(state.ipChangeHeld("alice")).isFalse();           // 최초 변화 기준 30s에 만료
    }

    @Test
    void records_and_reads_last_burst_band() {
        assertThat(state.lastBurstBand("alice")).isNull();          // 첫 관측 전(히스테리시스 기준 없음)
        state.recordBurstBand("alice", true);
        assertThat(state.lastBurstBand("alice")).isTrue();
        state.recordBurstBand("alice", false);
        assertThat(state.lastBurstBand("alice")).isFalse();
    }

    @Test
    void burst_band_record_preserves_ip_epoch_score_and_hold() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // hold 시작
        state.recordScore("alice", 10);
        state.recordScore("alice", 80);                              // bump → epoch 1
        state.recordBurstBand("alice", true);
        assertThat(state.lastSeenIp("alice")).isEqualTo("9.9.9.9");  // 다른 상태를 덮지 않는다
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(state.ipChangeHeld("alice")).isTrue();            // hold도 유지
        assertThat(state.recordScore("alice", 80)).isEqualTo(1L);    // 점수 기준도 유지(동일 점수 → bump 없음)
    }

    @Test
    void score_record_preserves_hold() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // hold 시작
        state.recordScore("alice", 40);
        assertThat(state.ipChangeHeld("alice")).isTrue();
    }

    @Test
    void evict_resets_risk_context_but_preserves_epoch() {
        state.recordScore("alice", 10);
        state.recordScore("alice", 80);                              // bump → epoch 1
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", "9.9.9.9");                          // hold 시작
        state.recordBurstBand("alice", true);
        state.evict("alice");
        assertThat(state.lastSeenIp("alice")).isNull();              // 다음 관측은 첫 관측(변화 아님)
        assertThat(state.ipChangeHeld("alice")).isFalse();           // hold도 리셋
        assertThat(state.lastBurstBand("alice")).isNull();           // 밴드 기준도 리셋
        // epoch는 보존 — GW가 단조(max)로 학습하므로 되돌리면 조회(옛 큰 epoch)/적재(새 작은 epoch)가
        // 영구히 갈려 그 주체가 캐시 불능이 된다. 세대 토큰은 뒤로 가지 않는다.
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(state.recordScore("alice", 50)).isEqualTo(1L);    // 리셋 후 첫 점수 = 기준 설정(bump 없음)
    }

    @Test
    void blank_or_null_ip_does_not_overwrite_baseline_or_start_hold() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", null);
        state.recordIp("alice", "  ");
        assertThat(state.lastSeenIp("alice")).isEqualTo("1.2.3.4");   // 미상 IP는 기준을 덮지 않음
        assertThat(state.ipChangeHeld("alice")).isFalse();            // 변화로도 치지 않음
    }
}
