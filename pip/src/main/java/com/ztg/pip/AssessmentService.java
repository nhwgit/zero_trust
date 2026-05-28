package com.ztg.pip;

import org.springframework.stereotype.Service;

import com.ztg.common.PipAssessment;
import com.ztg.common.RiskAssessment;
import com.ztg.common.RiskSignals;
import com.ztg.common.SubjectAttributes;

/**
 * PIP의 위험 평가 오케스트레이션 — 저장 속성 + 휘발성 신호 + 직전 IP를 모아 {@link RiskEngine}으로
 * 점수를 내고, 주체별 {@link SubjectRiskState}로 epoch를 갱신해 한 번에 {@link PipAssessment}로 묶는다.
 *
 * <p>순서가 의미를 가진다: ① 직전 IP를 <b>먼저</b> 읽어 IP 변화를 판정하고 점수를 낸 뒤,
 * ② 점수로 epoch를 갱신(변화 시 bump)하고, ③ 이번 IP를 직전 값으로 덮는다(다음 요청의 비교 기준).
 * 점수 산출(순수)과 상태 갱신(부수효과)을 이 한 곳에 모아 컨트롤러는 얇게 유지한다.
 */
@Service
public class AssessmentService {

    private final SubjectAttributeStore store;
    private final RiskEngine riskEngine;
    private final SubjectRiskState state;

    public AssessmentService(SubjectAttributeStore store, RiskEngine riskEngine, SubjectRiskState state) {
        this.store = store;
        this.riskEngine = riskEngine;
        this.state = state;
    }

    public PipAssessment assess(String subject, RiskSignals signals) {
        RiskSignals effective = signals == null ? RiskSignals.none() : signals;

        SubjectAttributes attrs = store.get(subject);
        String lastSeenIp = state.lastSeenIp(subject);                 // ① 변화 판정 기준(덮기 전에 읽는다)
        RiskAssessment risk = riskEngine.assess(attrs, effective, lastSeenIp);

        long epoch = state.recordScore(subject, risk.score());         // ② 점수 변화 시 epoch bump
        state.recordIp(subject, effective.sourceIp());                 // ③ 다음 비교 기준 갱신

        return new PipAssessment(attrs, risk, epoch);
    }
}
