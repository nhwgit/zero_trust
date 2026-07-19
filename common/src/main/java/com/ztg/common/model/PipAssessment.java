package com.ztg.common.model;

/**
 * PIP → PDP 평가 응답 — 한 번의 {@code POST /pip/assess}로 판단에 필요한 모든 맥락(속성+위험+epoch)을 준다.
 * PIP는 정보점이라 점수를 산출하되 임계 적용은 PDP 몫이다.
 *
 * @param epoch 주체의 현재 위험 epoch(능동 무효화 토큰)
 */
public record PipAssessment(SubjectAttributes attributes, RiskAssessment risk, long epoch) {
}
