package com.ztg.pdp.policy;

import com.ztg.pdp.client.PipClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ztg.common.model.Decision;
import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.PipAssessment;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/** 오케스트레이션 검증 — PIP 평가 실패 시 fail-close(DENY)인지, 판단이 지표로 집계되는지 확인한다. */
class PolicyDecisionServiceTest {

    private final PipClient pip = mock(PipClient.class);
    private final PolicyEngine engine = new PolicyEngine(9, 18, 80);
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final PolicyDecisionService service = new PolicyDecisionService(pip, engine, registry);

    @Test
    void pip_failure_fails_closed_to_indeterminate() {
        when(pip.assess(eq("alice"), any(RiskSignals.class)))
                .thenThrow(new RuntimeException("connection refused"));

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll", Map.of()));

        // 정책이 거부한 게 아니라 맥락이 없어 판단 불성립 — 게이트웨이가 이 결정을 캐시하지 않게 하는 근거.
        assertThat(res.decision()).isEqualTo(Decision.INDETERMINATE);
        assertThat(res.isAllowed()).isFalse();
        assertThat(res.reason()).contains("context unavailable");
        // PIP 장애로 인한 거부는 정책 거부와 구분해 집계된다.
        assertThat(registry.counter("ztg.pdp.decisions", "decision", "deny", "cause", "pip_error").count())
                .isEqualTo(1.0);
    }

    @Test
    void delegates_to_engine_when_pip_responds() {
        when(pip.assess(eq("alice"), any(RiskSignals.class)))
                .thenReturn(new PipAssessment(
                        new SubjectAttributes("alice", "finance", true, 10),
                        new RiskAssessment(10, List.of()), 3L));

        // context 없는 일반 리소스 = 기본 허용 경로. payroll이면 hour 미관측이 fail-close라 DENY가 된다(엔진 테스트).
        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/hello", Map.of()));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
        assertThat(res.epoch()).isEqualTo(3L);   // PIP epoch가 결정에 실려 게이트웨이로 역전파된다
        assertThat(registry.counter("ztg.pdp.decisions", "decision", "allow", "cause", "none").count())
                .isEqualTo(1.0);
    }

    @Test
    void payroll_hours_judged_by_gateway_observed_hour_not_local_clock() {
        // 시간 정책의 입력은 게이트웨이가 관측해 실은 hour-of-day다 — PDP 호스트가 어느 TZ든
        // 같은 관측값이면 같은 결과(시계 3개 → 관측 지점 1개 단일화). 22시 관측이면 payroll은 거부된다.
        when(pip.assess(eq("alice"), any(RiskSignals.class)))
                .thenReturn(new PipAssessment(
                        new SubjectAttributes("alice", "finance", true, 10),
                        new RiskAssessment(10, List.of()), 3L));

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll",
                Map.of(RiskSignals.CTX_HOUR_OF_DAY, "22")));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("business hours").contains("22");
    }
}
