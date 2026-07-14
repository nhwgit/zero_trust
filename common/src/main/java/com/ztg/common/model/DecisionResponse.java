package com.ztg.common.model;

import java.util.List;

/**
 * PDP → PEP 판단 응답.
 *
 * <p>위험적응 인가를 위해 결정에 <b>위험 내역</b>과 <b>epoch</b>를 함께 싣는다. {@code score}/{@code factors}는
 * "왜 이 결정인지"를 설명하고, {@code epoch}는 능동 캐시 무효화 토큰이다: 게이트웨이는 이 값을 학습해
 * 캐시 키에 반영하므로, 위험 변화(epoch bump) 시 옛 캐시가 키-아웃된다.
 *
 * @param decision ALLOW/DENY
 * @param reason   사람이 읽을 수 있는 사유(감사/디버깅용). PEP가 DENY 시 응답 헤더로 노출한다.
 * @param score    이 결정의 근거가 된 위험 점수(0~100). 위험 무관 결정은 0.
 * @param factors  점수에 기여한 신호 내역(설명용). 비어 있을 수 있다.
 * @param epoch    주체의 현재 위험 epoch(능동 무효화 토큰). 게이트웨이가 캐시 키로 학습.
 */
public record DecisionResponse(
        Decision decision,
        String reason,
        int score,
        List<RiskFactor> factors,
        long epoch) {

    public DecisionResponse {
        factors = factors == null ? List.of() : List.copyOf(factors);
    }

    /** 위험 맥락 없는 단순 허용(정책/기본 경로·내부 호출용). score=0, epoch=0. */
    public static DecisionResponse allow(String reason) {
        return new DecisionResponse(Decision.ALLOW, reason, 0, List.of(), 0L);
    }

    /** 위험 맥락 없는 단순 거부(fail-close·정책 거부용). score=0, epoch=0. */
    public static DecisionResponse deny(String reason) {
        return new DecisionResponse(Decision.DENY, reason, 0, List.of(), 0L);
    }

    /** 위험 평가를 동반한 허용 — 점수/내역/epoch를 게이트웨이로 역전파한다. */
    public static DecisionResponse allow(String reason, RiskAssessment risk, long epoch) {
        return new DecisionResponse(Decision.ALLOW, reason, risk.score(), risk.factors(), epoch);
    }

    /** 위험 평가를 동반한 거부 — 점수/내역/epoch를 게이트웨이로 역전파한다. */
    public static DecisionResponse deny(String reason, RiskAssessment risk, long epoch) {
        return new DecisionResponse(Decision.DENY, reason, risk.score(), risk.factors(), epoch);
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
