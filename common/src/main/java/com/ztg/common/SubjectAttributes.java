package com.ztg.common;

/**
 * PIP → PDP가 제공하는 주체의 맥락/속성. ABAC 정책 평가에 쓰인다.
 *
 * @param subject       주체 식별자
 * @param department    소속 부서(예: finance, engineering) — 부서 기반 정책에 사용
 * @param deviceTrusted 신뢰된(관리되는) 디바이스에서의 접근인지 — 디바이스 기반 정책에 사용
 * @param riskScore     위험 점수(0~100, 높을수록 위험) — 위험적응 정책에 사용
 */
public record SubjectAttributes(
        String subject,
        String department,
        boolean deviceTrusted,
        int riskScore) {
}
