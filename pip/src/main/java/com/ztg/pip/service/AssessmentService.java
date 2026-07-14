package com.ztg.pip.service;

import java.time.Clock;
import java.time.LocalTime;
import java.util.List;

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
 * 캐시를 키-아웃한다({@link com.ztg.common.fanout.EpochFanout}). 같은 점수 반복(epoch 불변)은 publish하지 않아 채널이 조용하다.
 *
 * <p><b>L4 신호:</b> 커널(XDP) 에이전트가 요청 밖(out-of-band)에서 소스 IP 단위 레이트 초과를
 * 보고하면({@link #applyL4RateSignal}), 플래그를 걸고 그 IP를 쓰는 주체들을 <b>즉시 재평가</b>한다 —
 * 점수 상승이 기존 경로(epoch bump → fan-out → 캐시 키-아웃)를 그대로 타므로, 신호원만 L7→커널로
 * 내려갔을 뿐 무효화 체계는 재사용이다.
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

    /** 테스트용 — 시계를 주입해 out-of-band 재평가의 시각 신호를 결정적으로 만든다. */
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
        RiskSignals effective = signals == null ? RiskSignals.none() : signals;

        SubjectAttributes attrs = store.get(subject);
        String lastSeenIp = state.lastSeenIp(subject);                 // ① 변화 판정 기준(덮기 전에 읽는다)
        // 이 요청의 출발지 IP에 커널 L4 플래그가 살아 있으면 위험 가중(만료면 null=무가중, fail-open).
        L4RateFlagStore.Flag l4Flag = l4Flags.activeFlag(effective.sourceIp());
        RiskAssessment risk = riskEngine.assess(attrs, effective, lastSeenIp, l4Flag);

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

    /**
     * 커널(XDP) 에이전트의 L4 레이트 신호를 반영한다: ① 소스 IP를 hold 동안 플래그하고,
     * ② 그 IP를 직전 관측으로 가진 주체들을 즉시 재평가한다 — rate-l4 가중으로 점수가 변하면
     * {@link #assess} 안에서 epoch bump + fan-out이 그대로 일어난다(능동 무효화 경로 재사용).
     *
     * <p>재평가 신호는 "PIP가 지금 아는 것"만 싣는다: 출발지 IP는 신호의 IP(직전 관측과 같아 IP 변화 무가중),
     * L7 레이트는 0(커널 신호는 L7 요청 수를 모름 — rate.l4와 rate.l7 분리 원칙), 시각은 현재.
     * 다음 실제 요청이 오면 게이트웨이가 진짜 휘발성 신호로 다시 평가한다.
     *
     * @return 재평가된 주체 목록(신호 IP를 쓰는 주체가 없으면 빈 목록 — 플래그는 남아 다음 평가에 반영)
     */
    public List<String> applyL4RateSignal(String sourceIp, long synsInWindow, int windowSeconds) {
        l4Flags.flag(sourceIp, synsInWindow, windowSeconds);
        List<String> affected = state.subjectsByLastSeenIp(sourceIp);
        int hour = LocalTime.now(clock).getHour();
        for (String subject : affected) {
            PipAssessment reassessed = assess(subject, new RiskSignals(sourceIp, 0, hour));
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
