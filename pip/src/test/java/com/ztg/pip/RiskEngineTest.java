package com.ztg.pip;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.ztg.common.RiskAssessment;
import com.ztg.common.RiskFactor;
import com.ztg.common.RiskSignals;
import com.ztg.common.SubjectAttributes;

/**
 * 위험 산출 단위 검증(L2) — 신호 조합별 점수·기여 팩터·밴드(임계 80 기준 ALLOW/DENY)를 확인한다.
 *
 * <p>핵심 데모 산수 고정: 정상 alice(baseline 10) = 10(ALLOW), 새 IP(+30)+폭주(+40) = 80(DENY 경계).
 * 가중치는 기본값(40/30/40/15, burst>60, 업무 9-18)으로 엔진을 만든다.
 */
class RiskEngineTest {

    private static final int THRESHOLD = 80;

    /** 기본 가중치로 엔진 생성(설정 디폴트와 동일). */
    private RiskEngine engine() {
        return new RiskEngine(40, 30, 40, 15, 60, 9, 18);
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
        // 경계: 정확히 임계(60)는 급증 아님, 61부터 급증.
        assertThat(engine().assess(alice(0), new RiskSignals("1.1.1.1", 60, 12), "1.1.1.1").factors())
                .extracting(RiskFactor::signal).doesNotContain("rate-burst");
        assertThat(engine().assess(alice(0), new RiskSignals("1.1.1.1", 61, 12), "1.1.1.1").factors())
                .extracting(RiskFactor::signal).contains("rate-burst");
    }

    @Test
    void null_signals_yield_baseline_only() {
        // 신호 미상(null)이어도 NPE 없이 baseline만 반영(방어적).
        RiskAssessment a = engine().assess(alice(10), null, "1.2.3.4");

        assertThat(a.score()).isEqualTo(10);
        assertThat(a.factors()).extracting(RiskFactor::signal).containsExactly("baseline");
    }
}
