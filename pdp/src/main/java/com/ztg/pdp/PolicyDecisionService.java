package com.ztg.pdp;

import io.micrometer.core.instrument.MeterRegistry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.ztg.common.Decision;
import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.SubjectAttributes;

/**
 * 판단 오케스트레이션 — PIP에서 맥락을 모아 {@link PolicyEngine}으로 평가한다.
 *
 * <p>설계 메모(fail-close): PIP 조회가 실패하면(네트워크/PIP 다운) 맥락 없이 판단할 수 없으므로
 * <b>DENY</b>한다. "판단 불가 = 차단"이 제로트러스트 안전 기본값이다.
 */
@Service
public class PolicyDecisionService {

    private static final Logger log = LoggerFactory.getLogger(PolicyDecisionService.class);

    private final PipClient pipClient;
    private final PolicyEngine policyEngine;
    private final MeterRegistry meterRegistry;

    public PolicyDecisionService(PipClient pipClient, PolicyEngine policyEngine, MeterRegistry meterRegistry) {
        this.pipClient = pipClient;
        this.policyEngine = policyEngine;
        this.meterRegistry = meterRegistry;
    }

    public DecisionResponse decide(DecisionRequest request) {
        SubjectAttributes attrs;
        try {
            attrs = pipClient.fetchAttributes(request.subject());
        } catch (RuntimeException e) {
            log.warn("PIP lookup failed for subject={}, failing closed: {}", request.subject(), e.toString());
            recordDecision("deny", "pip_error");
            return DecisionResponse.deny("context unavailable (PIP error): " + e.getMessage());
        }

        DecisionResponse response = policyEngine.evaluate(request, attrs);
        boolean allowed = response.decision() == Decision.ALLOW;
        recordDecision(allowed ? "allow" : "deny", allowed ? "none" : "policy");
        log.info("decision subject={} action={} resource={} -> {} ({})",
                request.subject(), request.action(), request.resource(),
                response.decision(), response.reason());
        return response;
    }

    /** PDP가 내린 판단을 카운터로 기록한다. cause로 정책거부(policy)와 PIP장애 fail-close(pip_error)를 구분. */
    private void recordDecision(String decision, String cause) {
        meterRegistry.counter("ztg.pdp.decisions", "decision", decision, "cause", cause).increment();
    }
}
