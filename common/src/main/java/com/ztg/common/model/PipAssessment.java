package com.ztg.common.model;

/**
 * PIP → PDP 평가 응답 — 한 번의 {@code POST /pip/assess}로 PDP가 판단에 필요한 모든 맥락을 받는다.
 *
 * <p>PIP는 정보점(information point)이라 <b>점수를 산출</b>하되 임계는 적용하지 않는다(임계는 PDP 몫).
 * 번들에 셋을 함께 싣는 이유:
 * <ul>
 *   <li>{@code attributes} — payroll 등 ABAC 정책이 쓰는 저장 속성(부서/디바이스).</li>
 *   <li>{@code risk} — 동적 위험 점수+내역. PDP가 임계와 비교해 ALLOW/DENY.</li>
 *   <li>{@code epoch} — 주체의 현재 위험 epoch(능동 무효화 토큰). 결정에 piggyback돼 게이트웨이로 간다.</li>
 * </ul>
 *
 * @param attributes 주체 저장 속성(부서/디바이스/baseline)
 * @param risk       동적 위험 평가(점수+기여 신호)
 * @param epoch      주체의 현재 위험 epoch
 */
public record PipAssessment(SubjectAttributes attributes, RiskAssessment risk, long epoch) {
}
