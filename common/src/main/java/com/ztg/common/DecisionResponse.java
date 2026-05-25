package com.ztg.common;

/**
 * PDP → PEP 판단 응답.
 *
 * @param decision ALLOW/DENY
 * @param reason   사람이 읽을 수 있는 사유(감사/디버깅용). PEP가 DENY 시 응답 헤더로 노출한다.
 */
public record DecisionResponse(Decision decision, String reason) {

    public static DecisionResponse allow(String reason) {
        return new DecisionResponse(Decision.ALLOW, reason);
    }

    public static DecisionResponse deny(String reason) {
        return new DecisionResponse(Decision.DENY, reason);
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
