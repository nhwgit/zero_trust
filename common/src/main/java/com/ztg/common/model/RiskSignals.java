package com.ztg.common.model;

import java.util.Map;

/**
 * 게이트웨이(PEP)가 관측해 전달하는 <b>휘발성</b> 위험 신호. 요청마다 달라진다.
 *
 * <p>저장 속성({@link SubjectAttributes}: 부서/디바이스/baseline)과 달리, 이 값들은 "지금 이 요청"의
 * 맥락이다. 게이트웨이는 모든 요청(캐시 히트 포함)을 보므로 레이트/IP의 권위 있는 관측자다(README 결정 #3).
 *
 * <p>전송 경로: 게이트웨이가 {@link DecisionRequest#context()}에 {@code CTX_*} 키로 실으면,
 * PDP가 {@link #fromContext(Map)}로 복원해 PIP에 전달한다. 키 상수를 한 곳에 둬 PEP/PDP가 같은
 * 어휘를 쓰게 한다(게이트웨이 주입은 step 3에서 채운다 — 그 전까지 context는 비어 {@link #none()}).
 *
 * @param sourceIp         이번 요청의 출발지 IP(직전 관측과 비교해 IP 변화 신호 산출)
 * @param requestsInWindow 슬라이딩 윈도우 동안 이 주체의 요청 수(레이트 급증 신호)
 * @param hourOfDay        요청 시각의 시(0~23, 업무시간 외 신호)
 */
public record RiskSignals(String sourceIp, int requestsInWindow, int hourOfDay) {

    /** 출발지 IP를 싣는 context 키(게이트웨이→PDP→PIP 공통 어휘). */
    public static final String CTX_SOURCE_IP = "source-ip";
    /** 윈도우 내 요청수를 싣는 context 키. */
    public static final String CTX_REQUESTS_IN_WINDOW = "requests-in-window";
    /** 요청 시각(시)을 싣는 context 키. */
    public static final String CTX_HOUR_OF_DAY = "hour-of-day";

    /** 신호가 없을 때의 중립값(IP 미상·레이트 0·시각 정오). 테스트/기본 경로용. */
    public static RiskSignals none() {
        return new RiskSignals(null, 0, 12);
    }

    /**
     * 게이트웨이가 {@link DecisionRequest#context()}에 실은 신호를 복원한다.
     * 키가 없거나 숫자가 깨졌으면 중립값으로 폴백한다(신호 부재는 위험 가중이 아니라 무가중).
     */
    public static RiskSignals fromContext(Map<String, String> context) {
        if (context == null || context.isEmpty()) {
            return none();
        }
        String ip = context.get(CTX_SOURCE_IP);
        int requests = parseOr(context.get(CTX_REQUESTS_IN_WINDOW), 0);
        int hour = parseOr(context.get(CTX_HOUR_OF_DAY), 12);
        return new RiskSignals(ip, requests, hour);
    }

    private static int parseOr(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
