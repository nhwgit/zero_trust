package com.ztg.pdp;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ztg.common.Decision;
import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.SubjectAttributes;

/**
 * 정책 엔진 단위 검증 — 완료 기준("조건을 바꾸면 동일 주체의 결과가 ALLOW↔DENY로 바뀐다")을
 * 부서/시간/디바이스/위험 축으로 각각 확인한다. 시각은 고정 Clock으로 결정적으로 만든다.
 */
class PolicyEngineTest {

    private static final int START = 9;
    private static final int END = 18;
    private static final int RISK_THRESHOLD = 80;

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

    @Test
    void payroll_allowed_for_finance_trusted_in_business_hours() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    void payroll_denied_when_department_not_finance() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("bob", "engineering", true, 10));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("finance");
    }

    @Test
    void payroll_denied_outside_business_hours() {
        DecisionResponse res = engineAtHour(22).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", true, 10));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("business hours");
    }

    @Test
    void payroll_denied_on_untrusted_device() {
        DecisionResponse res = engineAtHour(12).evaluate(
                payrollRequest(),
                new SubjectAttributes("alice", "finance", false, 10));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("device");
    }

    @Test
    void high_risk_score_denies_regardless_of_resource() {
        // payroll이 아닌 일반 리소스라도 위험점수가 임계치 이상이면 차단된다.
        DecisionResponse res = engineAtHour(12).evaluate(
                new DecisionRequest("alice", "GET", "/api/hello", Map.of()),
                new SubjectAttributes("alice", "finance", true, 95));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("risk");
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
                new SubjectAttributes("alice", "finance", true, 10));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    void non_payroll_resource_allowed_by_default() {
        DecisionResponse res = engineAtHour(3).evaluate(  // 업무시간 밖이어도 payroll 정책과 무관
                new DecisionRequest("alice", "GET", "/api/hello", Map.of()),
                new SubjectAttributes("alice", "engineering", false, 10));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
    }
}
