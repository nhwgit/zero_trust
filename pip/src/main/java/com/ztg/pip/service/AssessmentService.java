package com.ztg.pip.service;

import com.ztg.pip.fanout.EpochPublisher;
import com.ztg.pip.store.SubjectAttributeStore;
import com.ztg.pip.store.SubjectRiskState;
import org.springframework.stereotype.Service;

import com.ztg.common.model.PipAssessment;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;

/**
 * PIP의 위험 평가 오케스트레이션 — 저장 속성 + 휘발성 신호 + 직전 IP를 모아 {@link RiskEngine}으로
 * 점수를 내고, 주체별 {@link SubjectRiskState}로 epoch를 갱신해 한 번에 {@link PipAssessment}로 묶는다.
 *
 * <p>순서가 의미를 가진다: ① 직전 IP를 <b>먼저</b> 읽어 IP 변화를 판정하고 점수를 낸 뒤,
 * ② 점수로 epoch를 갱신(변화 시 bump)하고, ③ 이번 IP를 직전 값으로 덮는다(다음 요청의 비교 기준).
 * 점수 산출(순수)과 상태 갱신(부수효과)을 이 한 곳에 모아 컨트롤러는 얇게 유지한다.
 *
 * <p><b>fan-out(다중 GW):</b> epoch가 실제로 <b>올랐을 때만</b> {@link EpochPublisher}로 전파한다 —
 * 변화 순간을 권위자(PIP)가 알리므로, 위험을 유발하지 않은 게이트웨이도 자기 PDP 왕복을 기다리지 않고
 * 캐시를 키-아웃한다([[EpochFanout]]). 같은 점수 반복(epoch 불변)은 publish하지 않아 채널이 조용하다.
 */
@Service
public class AssessmentService {

    private final SubjectAttributeStore store;
    private final RiskEngine riskEngine;
    private final SubjectRiskState state;
    private final EpochPublisher epochPublisher;

    public AssessmentService(SubjectAttributeStore store, RiskEngine riskEngine, SubjectRiskState state,
                             EpochPublisher epochPublisher) {
        this.store = store;
        this.riskEngine = riskEngine;
        this.state = state;
        this.epochPublisher = epochPublisher;
    }

    public PipAssessment assess(String subject, RiskSignals signals) {
        RiskSignals effective = signals == null ? RiskSignals.none() : signals;

        SubjectAttributes attrs = store.get(subject);
        String lastSeenIp = state.lastSeenIp(subject);                 // ① 변화 판정 기준(덮기 전에 읽는다)
        RiskAssessment risk = riskEngine.assess(attrs, effective, lastSeenIp);

        long before = state.currentEpoch(subject);                     // bump 여부 판정 기준
        long epoch = state.recordScore(subject, risk.score());         // ② 점수 변화 시 epoch bump
        state.recordIp(subject, effective.sourceIp());                 // ③ 다음 비교 기준 갱신

        // epoch가 올랐으면(위험 변화) 모든 게이트웨이에 fan-out해 동시 무효화를 유발한다.
        // 단조 학습이라 중복/순서뒤바뀜 전파도 무해(게이트웨이가 max로만 채택).
        if (epoch > before) {
            epochPublisher.publish(subject, epoch);
        }

        return new PipAssessment(attrs, risk, epoch);
    }
}
