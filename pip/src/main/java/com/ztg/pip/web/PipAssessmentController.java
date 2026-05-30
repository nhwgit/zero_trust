package com.ztg.pip;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ztg.common.AssessRequest;
import com.ztg.common.PipAssessment;

/**
 * PIP의 위험 평가 표면. PDP가 판단 직전 호출한다.
 *
 * <p>{@code POST /pip/assess} — 입력 {@link AssessRequest}(주체+휘발성 신호), 출력 {@link PipAssessment}
 * (저장 속성+동적 위험점수+epoch). 속성 단순 조회({@code GET /pip/attributes/{subject}}, {@link PipController})와
 * 달리 게이트웨이 신호를 받아 점수를 산출하므로 본문 있는 POST를 쓴다.
 */
@RestController
public class PipAssessmentController {

    private final AssessmentService assessmentService;

    public PipAssessmentController(AssessmentService assessmentService) {
        this.assessmentService = assessmentService;
    }

    @PostMapping("/pip/assess")
    public PipAssessment assess(@RequestBody AssessRequest request) {
        return assessmentService.assess(request.subject(), request.signals());
    }
}
