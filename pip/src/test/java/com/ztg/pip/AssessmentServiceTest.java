package com.ztg.pip;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.ztg.common.PipAssessment;
import com.ztg.common.RiskSignals;

/**
 * PIP 평가 오케스트레이션 L2 — 점수 산출 + epoch 발급을 한 흐름으로 검증한다.
 * 핵심 시나리오: 같은 주체가 정상(저위험)에서 새 IP+폭주로 바뀌면 점수가 임계 위로 오르고
 * <b>epoch가 bump</b>된다 → 이것이 게이트웨이의 능동 캐시 무효화(재로그인 없는 ALLOW→DENY)를 떠받친다.
 */
class AssessmentServiceTest {

    /** RiskEngine은 @Value 기본값을 코드로 재현(미신뢰40/IP변화30/폭주40/업무외15, 폭주임계60, 업무 9-18). */
    private final RiskEngine riskEngine = new RiskEngine(40, 30, 40, 15, 60, 9, 18);
    private final SubjectRiskState state = new SubjectRiskState();
    private final AssessmentService service =
            new AssessmentService(new SubjectAttributeStore(), riskEngine, state);

    @Test
    void normal_then_new_ip_and_burst_raises_score_and_bumps_epoch() {
        // 1) 정상: alice(baseline 10, finance, 신뢰), 기존 IP, 폭주 없음, 업무시간 → score 10, epoch 0.
        PipAssessment first = service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));
        assertThat(first.attributes().subject()).isEqualTo("alice");
        assertThat(first.risk().score()).isEqualTo(10);
        assertThat(first.epoch()).isZero();

        // 2) 같은 세션에서 새 IP(+30) + 폭주 70>60(+40) → score 80(임계), 점수 변화 → epoch 1.
        PipAssessment second = service.assess("alice", new RiskSignals("9.9.9.9", 70, 12));
        assertThat(second.risk().score()).isEqualTo(80);
        assertThat(second.epoch()).isEqualTo(1L);
        // 설명 가능: 거부 사유에 실릴 기여 신호 내역이 두 신호를 모두 담는다.
        assertThat(second.risk().explain()).contains("ip-change").contains("rate-burst");
    }

    @Test
    void stable_risk_does_not_bump_epoch() {
        service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));   // epoch 0
        PipAssessment again = service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));
        assertThat(again.risk().score()).isEqualTo(10);
        assertThat(again.epoch()).isZero();   // 점수 동일 → 캐시 유지(불필요한 무효화 없음)
    }

    @Test
    void unknown_subject_is_max_risk() {
        // 미등록 주체는 보수적 기본 프로필(baseline 100, 미신뢰) → 점수 100으로 clamp.
        PipAssessment res = service.assess("mallory", RiskSignals.none());
        assertThat(res.risk().score()).isEqualTo(100);
    }

    @Test
    void null_signals_fall_back_to_neutral() {
        // 신호 누락(게이트웨이 미주입 등)은 위험 가중이 아니라 무가중 — baseline만 반영.
        PipAssessment res = service.assess("alice", null);
        assertThat(res.risk().score()).isEqualTo(10);
    }
}
