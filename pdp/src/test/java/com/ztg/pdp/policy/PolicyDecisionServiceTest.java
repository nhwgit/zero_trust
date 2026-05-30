package com.ztg.pdp.policy;

import com.ztg.pdp.client.PipClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
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
    private final PolicyEngine engine = new PolicyEngine(
            Clock.fixed(LocalDate.of(2026, 5, 31).atTime(12, 0).toInstant(ZoneOffset.UTC), ZoneOffset.UTC),
            9, 18, 80);
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final PolicyDecisionService service = new PolicyDecisionService(pip, engine, registry);

    @Test
    void pip_failure_fails_closed_to_deny() {
        when(pip.assess(eq("alice"), any(RiskSignals.class)))
                .thenThrow(new RuntimeException("connection refused"));

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll", Map.of()));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
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

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll", Map.of()));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
        assertThat(res.epoch()).isEqualTo(3L);   // PIP epoch가 결정에 실려 게이트웨이로 역전파된다
        assertThat(registry.counter("ztg.pdp.decisions", "decision", "allow", "cause", "none").count())
                .isEqualTo(1.0);
    }
}
