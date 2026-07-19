package com.ztg.common.model;

/**
 * PDP → PIP 위험 평가 요청. 게이트웨이가 관측한 신호를 함께 넘겨야 하므로 본문 있는 {@code POST /pip/assess}를 쓴다.
 *
 * @param signals 게이트웨이가 관측한 휘발성 신호(없으면 {@link RiskSignals#none()})
 */
public record AssessRequest(String subject, RiskSignals signals) {
}
