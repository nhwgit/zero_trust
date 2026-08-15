package com.ztg.common.model;

import java.util.List;

/**
 * PDP → PEP 판단 응답 — 결정에 위험 내역(score/factors)과 epoch를 함께 싣는다.
 * epoch는 능동 캐시 무효화 토큰으로, 게이트웨이가 캐시 키로 학습해 epoch bump 시 옛 캐시가 키-아웃된다.
 *
 * @param reason 사람이 읽을 수 있는 사유. PEP가 DENY 시 응답 헤더로 노출한다.
 * @param score  이 결정의 근거가 된 위험 점수(0~100). 위험 무관 결정은 0.
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

    /** 위험 맥락 없는 단순 거부(정책 거부용). score=0, epoch=0. */
    public static DecisionResponse deny(String reason) {
        return new DecisionResponse(Decision.DENY, reason, 0, List.of(), 0L);
    }

    /** 맥락 부재로 판단 불성립(fail-close). score/epoch의 0은 관측값이 아니라 미상. */
    public static DecisionResponse indeterminate(String reason) {
        return new DecisionResponse(Decision.INDETERMINATE, reason, 0, List.of(), 0L);
    }

    public static DecisionResponse allow(String reason, RiskAssessment risk, long epoch) {
        return new DecisionResponse(Decision.ALLOW, reason, risk.score(), risk.factors(), epoch);
    }

    public static DecisionResponse deny(String reason, RiskAssessment risk, long epoch) {
        return new DecisionResponse(Decision.DENY, reason, risk.score(), risk.factors(), epoch);
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
