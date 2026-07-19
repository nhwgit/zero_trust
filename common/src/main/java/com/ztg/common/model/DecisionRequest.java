package com.ztg.common.model;

import java.util.Map;

/**
 * PEP(Gateway) → PDP 판단 요청 — ABAC 평가의 입력.
 *
 * @param subject 인증된 주체 식별자(JWT의 preferred_username)
 * @param action  수행하려는 동작(HTTP 메서드)
 * @param context PEP가 추가로 실어 보내는 요청 맥락(예: source-ip). 비어 있을 수 있다.
 */
public record DecisionRequest(
        String subject,
        String action,
        String resource,
        Map<String, String> context) {
}
