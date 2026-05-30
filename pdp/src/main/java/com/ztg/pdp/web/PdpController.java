package com.ztg.pdp.web;

import com.ztg.pdp.policy.PolicyDecisionService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;

/**
 * PDP의 HTTP 표면. PEP(Gateway)가 매 요청마다 판단을 질의한다.
 *
 * <p>{@code POST /decision} — 입력 {@link DecisionRequest}, 출력 {@link DecisionResponse}.
 * 항상 200으로 응답하고, 허용/거부는 본문의 {@code decision}으로 전달한다(거부는 에러가 아니라 정상 판단).
 */
@RestController
public class PdpController {

    private final PolicyDecisionService decisionService;

    public PdpController(PolicyDecisionService decisionService) {
        this.decisionService = decisionService;
    }

    @PostMapping("/decision")
    public DecisionResponse decide(@RequestBody DecisionRequest request) {
        return decisionService.decide(request);
    }
}
