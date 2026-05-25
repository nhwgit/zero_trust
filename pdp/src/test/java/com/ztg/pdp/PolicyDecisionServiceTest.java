package com.ztg.pdp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ztg.common.Decision;
import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.SubjectAttributes;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/** 오케스트레이션 검증 — PIP 조회 실패 시 fail-close(DENY)인지, 판단이 지표로 집계되는지 확인한다. */
class PolicyDecisionServiceTest {

    private final PipClient pip = mock(PipClient.class);
    private final PolicyEngine engine = new PolicyEngine(
            Clock.fixed(LocalDate.of(2026, 5, 31).atTime(12, 0).toInstant(ZoneOffset.UTC), ZoneOffset.UTC),
            9, 18, 80);
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final PolicyDecisionService service = new PolicyDecisionService(pip, engine, registry);

    @Test
    void pip_failure_fails_closed_to_deny() {
        when(pip.fetchAttributes("alice")).thenThrow(new RuntimeException("connection refused"));

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll", Map.of()));

        assertThat(res.decision()).isEqualTo(Decision.DENY);
        assertThat(res.reason()).contains("context unavailable");
        // PIP 장애로 인한 거부는 정책 거부와 구분해 집계된다.
        assertThat(registry.counter("ztg.pdp.decisions", "decision", "deny", "cause", "pip_error").count())
                .isEqualTo(1.0);
    }

    @Test
    void delegates_to_engine_when_pip_responds() {
        when(pip.fetchAttributes("alice"))
                .thenReturn(new SubjectAttributes("alice", "finance", true, 10));

        DecisionResponse res = service.decide(new DecisionRequest("alice", "GET", "/api/payroll", Map.of()));

        assertThat(res.decision()).isEqualTo(Decision.ALLOW);
        assertThat(registry.counter("ztg.pdp.decisions", "decision", "allow", "cause", "none").count())
                .isEqualTo(1.0);
    }
}
