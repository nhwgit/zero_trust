package com.ztg.common;

import java.util.Map;

/**
 * PEP(Gateway) → PDP 판단 요청.
 *
 * <p>"누가({@code subject})가 무엇을({@code action})을 어떤 리소스({@code resource})에,
 * 어떤 맥락({@code context})에서" 접근하려는지를 담는다. ABAC 평가의 입력이다.
 *
 * @param subject  인증된 주체 식별자(여기서는 JWT의 preferred_username)
 * @param action   수행하려는 동작(HTTP 메서드: GET/POST/...)
 * @param resource 접근 대상 리소스 경로(예: {@code /api/payroll})
 * @param context  PEP가 추가로 실어 보내는 요청 맥락(예: source-ip). 비어 있을 수 있다.
 */
public record DecisionRequest(
        String subject,
        String action,
        String resource,
        Map<String, String> context) {
}
