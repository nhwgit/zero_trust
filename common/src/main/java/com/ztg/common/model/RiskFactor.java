package com.ztg.common.model;

/**
 * 위험 점수에 기여한 단일 신호 — 점수를 "설명 가능"하게 만드는 단위. 로그/응답 reason으로 그대로 노출된다.
 *
 * @param signal 신호 식별자(예: {@code ip-change}, {@code rate-burst})
 * @param detail 사람이 읽을 근거(예: {@code "source ip changed 1.2.3.4 -> 9.9.9.9"})
 */
public record RiskFactor(String signal, int points, String detail) {
}
