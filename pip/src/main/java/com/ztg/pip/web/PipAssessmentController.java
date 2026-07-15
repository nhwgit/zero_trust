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
 * PIP의 위험 평가 표면. PDP가 판단 직전 호출한다.
 *
 * <ul>
 *   <li>{@code POST   /pip/assess} — 입력 {@link AssessRequest}(주체+휘발성 신호), 출력 {@link PipAssessment}
 *       (저장 속성+동적 위험점수+epoch). 속성 단순 조회({@code GET /pip/attributes/{subject}},
 *       {@link PipController})와 달리 게이트웨이 신호를 받아 점수를 산출하므로 본문 있는 POST를 쓴다.</li>
 *   <li>{@code DELETE /pip/risk/{subject}} — 주체의 지속 위험 맥락(직전 IP·IP 변화 hold·직전 점수·밴드)을
 *       리셋한다(데모/스모크 재실행 결정성 — 이전 실행이 남긴 lastSeenIp가 첫 요청을 ip-change로 오탐하고,
 *       hold 도입 후엔 그 오탐이 창 동안 유지되므로 시간 대기 대신 명시 리셋이 필요). epoch는 보존된다
 *       ({@link SubjectRiskState#evict} — 게이트웨이 단조 학습과의 정합). 속성 PUT과 같은 데모 전용 표면.</li>
 * </ul>
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
