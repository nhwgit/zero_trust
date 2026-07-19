package com.ztg.pip.web;

import com.ztg.pip.service.AssessmentService;
import com.ztg.pip.store.SubjectRiskState;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ztg.common.model.AssessRequest;
import com.ztg.common.model.PipAssessment;

/**
 * PIP의 위험 평가 표면. {@code POST /pip/assess}는 PDP가 판단 직전 호출한다.
 *
 * <p>{@code DELETE /pip/risk/{subject}}는 데모/스모크 재실행 결정성을 위한 위험 맥락 리셋이다 —
 * 이전 실행이 남긴 lastSeenIp가 첫 요청을 ip-change로 오탐하는 것을 막는다.
 * epoch는 보존한다(게이트웨이 단조 학습과의 정합).
 */
@RestController
public class PipAssessmentController {

    private final AssessmentService assessmentService;
    private final SubjectRiskState riskState;

    public PipAssessmentController(AssessmentService assessmentService, SubjectRiskState riskState) {
        this.assessmentService = assessmentService;
        this.riskState = riskState;
    }

    @PostMapping("/pip/assess")
    public PipAssessment assess(@RequestBody AssessRequest request) {
        return assessmentService.assess(request.subject(), request.signals());
    }

    @DeleteMapping("/pip/risk/{subject}")
    public void resetRisk(@PathVariable String subject) {
        riskState.evict(subject);
    }
}
