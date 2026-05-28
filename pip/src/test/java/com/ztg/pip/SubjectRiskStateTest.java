package com.ztg.pip;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** 주체 위험 상태(직전 IP) 검증 — 기록/조회/리셋과 미상 IP 무시. */
class SubjectRiskStateTest {

    private final SubjectRiskState state = new SubjectRiskState();

    @Test
    void records_and_reads_last_seen_ip() {
        assertThat(state.lastSeenIp("alice")).isNull();   // 첫 관측 전
        state.recordIp("alice", "1.2.3.4");
        assertThat(state.lastSeenIp("alice")).isEqualTo("1.2.3.4");
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
