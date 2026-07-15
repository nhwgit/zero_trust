package com.ztg.pip.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;

/**
 * 위험 산출 단위 검증(L2) — 신호 조합별 점수·기여 팩터·밴드(임계 80 기준 ALLOW/DENY)를 확인한다.
 *
 * <p>핵심 데모 산수 고정: 정상 alice(baseline 10) = 10(ALLOW), 새 IP(+30)+폭주(+40) = 80(DENY 경계).
 * 가중치는 기본값(40/30/40/15, burst>60, 업무 9-18)으로 엔진을 만든다.
 */
class RiskEngineTest {

    private static final int THRESHOLD = 80;

    /** 기본 가중치로 엔진 생성(설정 디폴트와 동일 — 폭주 진입>60/해제≤40). */
    private RiskEngine engine() {
        return new RiskEngine(40, 30, 40, 40, 15, 60, 40, 9, 18);
    }

    /** finance/신뢰/baseline 지정 주체. */
    private static SubjectAttributes alice(int baseline) {
        return new SubjectAttributes("alice", "finance", true, baseline);
    }

    private static boolean denied(RiskAssessment a) {
        return a.score() >= THRESHOLD;
    }

    @Test
    void quiet_subject_scores_baseline_only_and_allows() {
        // 정상: trusted, 같은 IP, 레이트 낮음, 업무시간 → baseline 10만.
        RiskAssessment a = engine().assess(
                alice(10),
                new RiskSignals("1.2.3.4", 5, 12),
                "1.2.3.4");

        assertThat(a.score()).isEqualTo(10);
        assertThat(a.factors()).extracting(RiskFactor::signal).containsExactly("baseline");
        assertThat(denied(a)).isFalse();
    }

    @Test
    void new_ip_plus_burst_crosses_threshold_and_denies() {
        // 데모 핵심: 새 IP(+30) + 폭주(+40) + baseline 10 = 80 → DENY(재로그인 없이 위험 상승).
        RiskAssessment a = engine().assess(
                alice(10),
                new RiskSignals("9.9.9.9", 100, 12),   // 직전 1.2.3.4와 다름, 윈도우 100 > 60
                "1.2.3.4");

        assertThat(a.score()).isEqualTo(80);
        assertThat(a.factors()).extracting(RiskFactor::signal)
                .containsExactlyInAnyOrder("baseline", "ip-change", "rate-burst");
        assertThat(denied(a)).isTrue();
        assertThat(a.explain()).contains("ip changed").contains("burst threshold");
    }

    @Test
    void first_observation_does_not_count_as_ip_change() {
        // lastSeenIp=null(첫 관측)이면 IP 변화로 치지 않는다 → baseline만.
        RiskAssessment a = engine().assess(
                alice(10),
                new RiskSignals("9.9.9.9", 5, 12),
                null);

        assertThat(a.factors()).extracting(RiskFactor::signal).containsExactly("baseline");
        assertThat(a.score()).isEqualTo(10);
    }

    @Test
    void same_ip_is_not_a_change() {
        RiskAssessment a = engine().assess(
                alice(10),
                new RiskSignals("1.2.3.4", 5, 12),
                "1.2.3.4");

        assertThat(a.factors()).extracting(RiskFactor::signal).doesNotContain("ip-change");
    }

    @Test
    void untrusted_device_and_off_hours_add_up() {
        // 미신뢰 디바이스(+40) + 업무시간 외(+15) + baseline 20 = 75 → 임계 미만이지만 누적 확인.
        RiskAssessment a = engine().assess(
                new SubjectAttributes("bob", "engineering", false, 20),
                new RiskSignals("1.1.1.1", 5, 3),   // 03시 = 업무시간 밖
                "1.1.1.1");

        assertThat(a.score()).isEqualTo(75);
        assertThat(a.factors()).extracting(RiskFactor::signal)
                .containsExactlyInAnyOrder("baseline", "device-untrusted", "off-hours");
        assertThat(denied(a)).isFalse();
    }

    @Test
    void score_is_clamped_to_100() {
        // 미등록 주체(baseline 100) + 다른 신호들이 더해져도 100을 넘지 않는다.
        RiskAssessment a = engine().assess(
                new SubjectAttributes("mallory", "unknown", false, 100),
                new RiskSignals("9.9.9.9", 100, 3),
                "1.1.1.1");

        assertThat(a.score()).isEqualTo(100);
        assertThat(denied(a)).isTrue();
    }

    @Test
    void burst_threshold_is_exclusive_boundary() {
        // 경계: 직전 밴드 없음(첫 관측) 기준 — 정확히 진입 임계(60)는 급증 아님, 61부터 급증.
        assertThat(engine().assess(alice(0), new RiskSignals("1.1.1.1", 60, 12), "1.1.1.1").factors())
                .extracting(RiskFactor::signal).doesNotContain("rate-burst");
        assertThat(engine().assess(alice(0), new RiskSignals("1.1.1.1", 61, 12), "1.1.1.1").factors())
                .extracting(RiskFactor::signal).contains("rate-burst");
    }

    @Test
    void burst_band_holds_between_thresholds_when_prior_band_was_burst() {
        // 히스테리시스: 사이 구간(40 < r ≤ 60)은 직전 밴드를 따른다 — 진동해도 점수(→epoch)가 출렁이지 않는 근거.
        RiskEngine e = engine();
        assertThat(e.burstBand(50, Boolean.TRUE)).isTrue();     // 직전 폭주: 유지
        assertThat(e.burstBand(50, Boolean.FALSE)).isFalse();   // 직전 정상: 진입 아님
        assertThat(e.burstBand(50, null)).isFalse();            // 첫 관측: 진입 임계만 적용
        assertThat(e.burstBand(40, Boolean.TRUE)).isFalse();    // 해제 임계(≤40) 도달: 해제
        assertThat(e.burstBand(61, Boolean.FALSE)).isTrue();    // 진입 임계 초과: 무조건 진입
    }

    @Test
    void held_burst_band_keeps_rate_burst_weight_and_explains_hysteresis() {
        // 폭주 중 레이트가 사이 구간(50)으로 내려와도 직전 밴드=폭주면 rate-burst 가중이 유지된다(같은 신호명·가중치).
        RiskAssessment held = engine().assess(alice(10), new RiskSignals("1.1.1.1", 50, 12), "1.1.1.1",
                false, Boolean.TRUE, null);
        assertThat(held.score()).isEqualTo(50);   // baseline 10 + rate-burst 40
        assertThat(held.factors()).extracting(RiskFactor::signal).contains("rate-burst");
        assertThat(held.explain()).contains("hold burst band");

        // 해제 임계 이하(30)로 내려오면 그때 가중이 빠진다 — 한 번의 점수 변화로 수렴.
        RiskAssessment exited = engine().assess(alice(10), new RiskSignals("1.1.1.1", 30, 12), "1.1.1.1",
                false, Boolean.TRUE, null);
        assertThat(exited.score()).isEqualTo(10);
        assertThat(exited.factors()).extracting(RiskFactor::signal).doesNotContain("rate-burst");
    }

    @Test
    void held_ip_change_keeps_weight_after_baseline_caught_up() {
        // hold 창 안: 비교 기준(lastSeenIp)이 이미 새 IP로 덮여 "지금은 변화 아님"이어도 ip-change 가중이 유지된다.
        // 순간 신호였다면 바뀐 직후 재평가에서 바로 빠져 DENY가 1~수초 스파이크로 끝난다(재시도 우회).
        RiskAssessment held = engine().assess(
                alice(10), new RiskSignals("9.9.9.9", 5, 12), "9.9.9.9", true, null, null);

        assertThat(held.score()).isEqualTo(40);   // baseline 10 + ip-change 30
        assertThat(held.factors()).extracting(RiskFactor::signal).contains("ip-change");
        assertThat(held.explain()).contains("within hold window");
    }

    @Test
    void fresh_change_with_active_hold_counts_once() {
        // hold 창 안에서 또 변화(회전)해도 같은 신호가 이중 가산되지 않는다 — 설명은 구체적인 쪽(변화 순간)을 쓴다.
        RiskAssessment a = engine().assess(
                alice(10), new RiskSignals("8.8.8.8", 5, 12), "9.9.9.9", true, null, null);

        assertThat(a.score()).isEqualTo(40);      // +30 한 번만
        assertThat(a.explain()).contains("9.9.9.9 -> 8.8.8.8");
    }

    @Test
    void hold_expired_and_same_ip_drops_ip_change() {
        // 창 경과 후(held=false) 같은 IP면 가중이 빠진다 — 한 번의 점수 하강으로 수렴(가역성).
        RiskAssessment a = engine().assess(
                alice(10), new RiskSignals("9.9.9.9", 5, 12), "9.9.9.9", false, null, null);

        assertThat(a.score()).isEqualTo(10);
        assertThat(a.factors()).extracting(RiskFactor::signal).doesNotContain("ip-change");
    }

    @Test
    void exit_threshold_above_enter_threshold_fails_fast() {
        // 해제 임계 > 진입 임계는 히스테리시스가 뒤집힌 오설정 — 기동 시점에 즉시 실패해야 한다.
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new RiskEngine(40, 30, 40, 40, 15, 60, 61, 9, 18))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("burst-exit-threshold");
    }

    @Test
    void l4_rate_flag_adds_kernel_weight() {
        // 커널(XDP) L4 플래그(+40): 미신뢰 디바이스(+40) + baseline 10 = 90 → DENY.
        // 토큰 없는 SYN 플러드는 L7 레이트(requestsInWindow)에 안 잡혀도 L4 축이 위험을 올린다.
        RiskAssessment a = engine().assess(
                new SubjectAttributes("alice", "finance", false, 10),
                new RiskSignals("1.2.3.4", 5, 12),
                "1.2.3.4",
                false,
                null,
                new com.ztg.pip.store.L4RateFlagStore.Flag("1.2.3.4", 87, 5, Long.MAX_VALUE));

        assertThat(a.score()).isEqualTo(90);
        assertThat(a.factors()).extracting(RiskFactor::signal)
                .containsExactlyInAnyOrder("baseline", "device-untrusted", "rate-l4");
        assertThat(denied(a)).isTrue();
        assertThat(a.explain()).contains("kernel(XDP)").contains("87 SYNs");
    }

    @Test
    void null_signals_yield_baseline_only() {
        // 신호 미상(null)이어도 NPE 없이 baseline만 반영(방어적).
        RiskAssessment a = engine().assess(alice(10), null, "1.2.3.4");

        assertThat(a.score()).isEqualTo(10);
        assertThat(a.factors()).extracting(RiskFactor::signal).containsExactly("baseline");
    }
}
