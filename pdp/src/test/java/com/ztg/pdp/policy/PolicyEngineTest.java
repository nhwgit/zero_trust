package com.ztg.pdp.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ztg.common.model.Decision;
import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.SubjectAttributes;

/**
 * 정책 엔진 단위 검증 — 완료 기준("조건을 바꾸면 동일 주체의 결과가 ALLOW↔DENY로 바뀐다")을
 * 부서/시간/디바이스/위험 축으로 각각 확인한다. 시각은 고정 Clock으로 결정적으로 만든다.
 *
 * <p>위험 점수는 정적 {@code attrs.riskScore()}가 아니라 PIP가 산출한 동적
 * {@link RiskAssessment}에서 온다. 그래서 위험 축 테스트는 RiskAssessment로 점수를 준다.
 */
class PolicyEngineTest {

    private static final int START = 9;
    private static final int END = 18;
    private static final int RISK_THRESHOLD = 80;
    private static final long EPOCH = 7L;   // 결정에 그대로 실려 게이트웨이로 가는지 확인용 sentinel

    /** 주어진 시(hour, UTC)에 멈춘 시계로 엔진을 만든다. */
    private PolicyEngine engineAtHour(int hour) {
        Clock fixed = Clock.fixed(
                LocalDate.of(2026, 5, 31).atTime(hour, 0).toInstant(ZoneOffset.UTC),
                ZoneOffset.UTC);
        return new PolicyEngine(fixed, START, END, RISK_THRESHOLD);
    }

    private static DecisionRequest payrollRequest() {
        return new DecisionRequest("alice", "GET", "/api/payroll", Map.of());
    }

    /** 위험 신호 없는 저위험 평가(payroll 축 테스트에서 위험 정책이 끼어들지 않도록). */
    private static RiskAssessment lowRisk() {
        return new RiskAssessment(10, List.of());
    }

    @Test
    void payroll_allowed_for_finance_trusted_in_business_hours() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
        assertThat(res.epoch()).isEqualTo(EPOCH);   // 허용에도 epoch가 실린다(게이트웨이 학습용)
    }

    @Test
    void payroll_denied_when_department_not_finance() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("bob", "engineering", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("finance");
    }

    @Test
    void payroll_denied_outside_business_hours() {
        DecisionResponse res = engineAtHour(22).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("business hours");
    }

    @Test
    void payroll_denied_on_untrusted_device() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", false, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("device");
    }

    @Test
    void high_dynamic_risk_denies_regardless_of_resource() {
        // payroll이 아닌 일반 리소스라도 PIP가 낸 동적 위험점수가 임계치 이상이면 차단된다.
        // 거부 사유에 기여 신호 내역(explain)이 실려 설명 가능해야 한다.
        RiskAssessment risk = new RiskAssessment(95, List.of(
                new RiskFactor("ip-change", 30, "source ip changed 1.1.1.1 -> 9.9.9.9")));
        DecisionResponse res = engineAtHour(12).evaluate(
                new DecisionRequest("alice", "GET", "/api/hello", Map.of()),
                new SubjectAttributes("alice", "finance", true, 10), risk, EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("risk").contains("ip-change");
        assertThat(res.score()).isEqualTo(95);
        assertThat(res.epoch()).isEqualTo(EPOCH);
    }

    @Test
    void payroll_allowed_with_24h_window_at_any_hour() {
        // 업무시간 창을 0-24(하루 종일)로 열면 한밤(3시)에도 finance/신뢰면 허용된다.
        // 회귀 방지: end=24를 LocalTime.of(24,0)으로 만들면 DateTimeException → 500. 분리 처리해야 한다.
        Clock fixed = Clock.fixed(
                LocalDate.of(2026, 5, 31).atTime(3, 0).toInstant(ZoneOffset.UTC),
                ZoneOffset.UTC);
        PolicyEngine engine = new PolicyEngine(fixed, 0, 24, RISK_THRESHOLD);

        DecisionResponse res = engine.evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    void risk_score_exactly_at_threshold_denies() {
        // 경계: 동적 위험점수 == 임계치(80)도 차단되어야 한다(>= 의미 고정). 79는 통과해야 한다.
        DecisionRequest req = new DecisionRequest("alice", "GET", "/api/hello", Map.of());
        SubjectAttributes attrs = new SubjectAttributes("alice", "finance", true, 10);

        assertThat(engineAtHour(12).evaluate(req, attrs, new RiskAssessment(RISK_THRESHOLD, List.of()), EPOCH).decision())
                .isEqualTo(Decision.DENY);
        assertThat(engineAtHour(12).evaluate(req, attrs, new RiskAssessment(RISK_THRESHOLD - 1, List.of()), EPOCH).decision())
                .isEqualTo(Decision.ALLOW);
    }

    @Test
    void payroll_allowed_at_business_hour_start_boundary() {
        // 경계: 시작 정각(09:00)은 업무시간 안이다(isBefore(start)가 false).
        DecisionResponse res = engineAtHour(START).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    void payroll_denied_at_business_hour_end_boundary() {
        // 경계: 끝 정각(18:00)은 업무시간 밖이다(isBefore(end)가 false). 끝값은 배타적.
        DecisionResponse res = engineAtHour(END).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("business hours");
    }

    @Test
    void payroll_denied_one_hour_before_business_hour_start() {
        // 경계: 시작 직전(08:00)은 업무시간 밖이다.
        DecisionResponse res = engineAtHour(START - 1).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("business hours");
    }

    @Test
    void non_payroll_resource_allowed_by_default() {
        DecisionResponse res = engineAtHour(3).evaluate(  // 업무시간 밖이어도 payroll 정책과 무관
                new DecisionRequest("alice", "GET", "/api/hello", Map.of()),
                new SubjectAttributes("alice", "engineering", false, 10), lowRisk(), EPOCH);

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }
}
