package com.ztg.common;

/**
 * PDP → PIP 위험 평가 요청. "이 주체를, 이 휘발성 신호 맥락에서 평가하라."
 *
 * <p>주체 속성 조회({@code GET /pip/attributes})와 달리, 평가는 게이트웨이가 관측한 신호
 * ({@link RiskSignals})를 함께 넘겨야 하므로 본문이 있는 {@code POST /pip/assess}를 쓴다.
 *
 * @param subject 평가 대상 주체 식별자
 * @param signals 게이트웨이가 관측한 휘발성 신호(없으면 {@link RiskSignals#none()})
 */
public record AssessRequest(String subject, RiskSignals signals) {
}
