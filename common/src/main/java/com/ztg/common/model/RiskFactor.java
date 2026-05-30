package com.ztg.common.model;

/**
 * 위험 점수에 기여한 단일 신호. 점수를 "설명 가능"하게 만드는 단위다.
 *
 * <p>지속검증(D1)의 핵심은 차단 자체가 아니라 <b>왜 차단했는지</b>를 댈 수 있는 것이다.
 * 각 {@code RiskFactor}는 "어떤 신호가({@code signal}) 몇 점({@code points}) 왜({@code detail})"를 담아
 * 로그/응답 reason으로 그대로 노출된다.
 *
 * @param signal 신호 식별자(예: {@code ip-change}, {@code rate-burst})
 * @param points 이 신호가 더한 위험 점수(양수)
 * @param detail 사람이 읽을 근거(예: {@code "source ip changed 1.2.3.4 -> 9.9.9.9"})
 */
public record RiskFactor(String signal, int points, String detail) {
}
