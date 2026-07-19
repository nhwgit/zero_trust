package com.ztg.pip.service;

import java.time.Clock;
import java.time.LocalTime;
import java.util.List;
import java.util.stream.Collectors;

import com.ztg.pip.fanout.EpochPublisher;
import com.ztg.pip.store.L4RateFlagStore;
import com.ztg.pip.store.SubjectAttributeStore;
import com.ztg.pip.store.SubjectRiskState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ztg.common.model.PipAssessment;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;

/**
 * PIP 위험 평가 오케스트레이션 — 저장 속성 + 휘발성 신호 + 직전 상태를 모아 {@link RiskEngine}으로
 * 점수를 내고, {@link SubjectRiskState}로 epoch를 갱신해 {@link PipAssessment}로 묶는다.
 * epoch가 실제로 오른 순간만 {@link EpochPublisher}로 다중 GW fan-out 한다.
 */
@Service
public class AssessmentService {

    private static final Logger log = LoggerFactory.getLogger(AssessmentService.class);

    private final SubjectAttributeStore store;
    private final RiskEngine riskEngine;
    private final SubjectRiskState state;
    private final EpochPublisher epochPublisher;
    private final L4RateFlagStore l4Flags;
    private final Clock clock;

    @Autowired
    public AssessmentService(SubjectAttributeStore store, RiskEngine riskEngine, SubjectRiskState state,
                             EpochPublisher epochPublisher, L4RateFlagStore l4Flags) {
        this(store, riskEngine, state, epochPublisher, l4Flags, Clock.systemDefaultZone());
    }

    /** 테스트용 — 시계 주입으로 out-of-band 재평가의 시각 신호를 결정적으로 만든다. */
    AssessmentService(SubjectAttributeStore store, RiskEngine riskEngine, SubjectRiskState state,
                      EpochPublisher epochPublisher, L4RateFlagStore l4Flags, Clock clock) {
        this.store = store;
        this.riskEngine = riskEngine;
        this.state = state;
        this.epochPublisher = epochPublisher;
        this.l4Flags = l4Flags;
        this.clock = clock;
    }

    public PipAssessment assess(String subject, RiskSignals signals) {
        return assess(subject, signals, true);
    }

    /**
     * 평가 본체. 순서가 의미를 가진다: ① 직전 상태를 먼저 읽어 판정하고 ② epoch 갱신 ③ 이번 관측을
     * 다음 비교 기준으로 덮는다. {@code recordBand=false}는 L4 재평가 전용 — 그 경로의
     * {@code requestsInWindow=0}은 미상이지 실측이 아니라, 밴드 기준을 가짜 0으로 덮으면
     * 실제 폭주 중인 주체의 히스테리시스가 발산한다.
     */
    private PipAssessment assess(String subject, RiskSignals signals, boolean recordBand) {
        RiskSignals effective = signals == null ? RiskSignals.none() : signals;

        SubjectAttributes attrs = store.get(subject);
        String lastSeenIp = state.lastSeenIp(subject);
        boolean ipChangeHeld = state.ipChangeHeld(subject);
        Boolean priorBand = state.lastBurstBand(subject);
        // L4 플래그 키는 패킷 소스 IP — 논리 축(XFF 기반)이 아닌 네트워크 축으로 맞춰야 LB 뒤에서도 매칭된다.
        String networkIp = effective.effectiveNetworkIp();
        L4RateFlagStore.Flag l4Flag = l4Flags.activeFlag(networkIp);
        RiskAssessment risk = riskEngine.assess(attrs, effective, lastSeenIp, ipChangeHeld, priorBand, l4Flag);

        long before = state.currentEpoch(subject);
        long epoch = state.recordScore(subject, risk.score(),
                risk.factors().stream().map(RiskFactor::signal).collect(Collectors.toSet()));
        state.recordIps(subject, effective.sourceIp(), networkIp);
        if (recordBand) {
            // 점수에 반영된 판정과 같은 순수 함수를 같은 입력으로 다시 불러 항상 일치한다.
            state.recordBurstBand(subject, riskEngine.burstBand(effective.requestsInWindow(), priorBand));
        }

        // 단조 학습이라 중복/순서뒤바뀜 전파도 무해(게이트웨이가 max로만 채택).
        if (epoch > before) {
            epochPublisher.publish(subject, epoch);
        }

        return new PipAssessment(attrs, risk, epoch);
    }

    /**
     * 커널(XDP)의 L4 레이트 신호: 소스 IP를 hold 동안 플래그하고, 그 IP를 네트워크 축 직전 관측으로
     * 가진 주체들을 즉시 재평가한다 — 점수 변화는 기존 epoch bump + fan-out 경로를 그대로 탄다.
     *
     * <p>재평가 신호는 "PIP가 지금 아는 것"만 싣는다: 논리 IP는 주체의 직전 관측 그대로(패킷 IP를 논리
     * 축에 실으면 LB 뒤에서 ip-change 오탐 + 기준 오염), L7 레이트는 0(커널은 L7 요청 수를 모름 —
     * 미상이므로 밴드 기준도 기록하지 않는다, {@code recordBand=false}).
     *
     * @param sourceIp 커널이 관측한 패킷 소스 IP(네트워크 축)
     * @return 재평가된 주체 목록(없으면 빈 목록 — 플래그는 남아 다음 평가에 반영)
     */
    public List<String> applyL4RateSignal(String sourceIp, long synsInWindow, int windowSeconds) {
        l4Flags.flag(sourceIp, synsInWindow, windowSeconds);
        List<String> affected = state.subjectsByNetworkIp(sourceIp);
        int hour = LocalTime.now(clock).getHour();
        for (String subject : affected) {
            PipAssessment reassessed =
                    assess(subject, new RiskSignals(state.lastSeenIp(subject), sourceIp, 0, hour), false);
            log.info("l4-rate signal ip={} syns={}/{}s -> reassess subject={} score={} epoch={}",
                    sourceIp, synsInWindow, windowSeconds, subject,
                    reassessed.risk().score(), reassessed.epoch());
        }
        if (affected.isEmpty()) {
            log.info("l4-rate signal ip={} syns={}/{}s -> no active subject (flag held for next assess)",
                    sourceIp, synsInWindow, windowSeconds);
        }
        return affected;
    }
}
