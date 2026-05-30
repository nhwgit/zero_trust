package com.ztg.pip.store;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** 주체 위험 상태(직전 IP + epoch) 검증 — 기록/조회/리셋, 미상 IP 무시, 점수 변화 시 epoch bump. */
class SubjectRiskStateTest {

    private final SubjectRiskState state = new SubjectRiskState();

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
    void evict_resets_epoch_and_ip() {
        state.recordScore("alice", 10);
        state.recordScore("alice", 80);
        state.recordIp("alice", "1.2.3.4");
        state.evict("alice");
        assertThat(state.currentEpoch("alice")).isZero();           // 첫 관측부터 다시
        assertThat(state.lastSeenIp("alice")).isNull();
    }

    @Test
    void blank_or_null_ip_does_not_overwrite_baseline() {
        state.recordIp("alice", "1.2.3.4");
        state.recordIp("alice", null);
        state.recordIp("alice", "  ");
        assertThat(state.lastSeenIp("alice")).isEqualTo("1.2.3.4");   // 미상 IP는 기준을 덮지 않음
    }

    @Test
    void evict_clears_state_for_demo_reset() {
        state.recordIp("alice", "1.2.3.4");
        state.evict("alice");
        assertThat(state.lastSeenIp("alice")).isNull();   // 다음 관측은 첫 관측으로 취급
    }
}
