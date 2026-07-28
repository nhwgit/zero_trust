package com.ztg.common.model;

import java.util.Map;

/**
 * 게이트웨이(PEP)가 관측해 요청마다 전달하는 휘발성 위험 신호.
 *
 * <p>IP는 두 좌표계로 나뉜다: {@code sourceIp}(논리 축, 신뢰 프록시 XFF 반영 — ip-change 판정·캐시 키)와
 * {@code networkIp}(네트워크 축, 에지 피어 = 커널(XDP)이 에지에서 패킷 소스로 보는 좌표 — L4 신호↔주체
 * 번역). 직결에선 에지 피어가 곧 소켓 피어이고, LB 에지 배치에선 LB가 PROXY protocol로 광고한 원
 * 클라이언트다. LB/프록시 뒤에선 두 축이 다르다. 폴백 규칙은 {@link #effectiveNetworkIp()} 한 곳에 둔다.
 *
 * @param sourceIp         출발지 IP(논리 축), {@code null}=미상
 * @param networkIp        에지 피어 IP(네트워크 축), {@code null}=미상
 * @param requestsInWindow 슬라이딩 윈도우 내 이 주체의 요청 수
 * @param hourOfDay        요청 시각의 시(0~23), {@code null}=미상
 */
public record RiskSignals(String sourceIp, String networkIp, int requestsInWindow, Integer hourOfDay) {

    public static final String CTX_SOURCE_IP = "source-ip";
    public static final String CTX_NETWORK_IP = "network-ip";
    public static final String CTX_REQUESTS_IN_WINDOW = "requests-in-window";
    public static final String CTX_HOUR_OF_DAY = "hour-of-day";

    /** 직결(프록시 없음) 신호 — 두 축이 같은 좌표이므로 네트워크 축을 생략한다. */
    public static RiskSignals direct(String sourceIp, int requestsInWindow, int hourOfDay) {
        return new RiskSignals(sourceIp, null, requestsInWindow, hourOfDay);
    }

    /**
     * 신호가 없을 때의 중립값(IP·시각 미상, 레이트 0). 부재는 위험 가중이 아니다.
     * 시각은 특정 시가 아니라 미상(null) — 어떤 시를 골라도 업무시간 설정에 따라 중립이 아닐 수 있다.
     */
    public static RiskSignals none() {
        return new RiskSignals(null, null, 0, null);
    }

    /**
     * 네트워크 축 IP. 미제공이면 논리 축으로 폴백한다 — 직결에선 두 좌표가 실제로 같아 폴백이 곧 사실이다.
     * 두 축의 폴백 규칙은 이 메서드가 유일한 정의다(수신 측에서 재구현하지 말 것).
     */
    public String effectiveNetworkIp() {
        return networkIp != null && !networkIp.isBlank() ? networkIp : sourceIp;
    }

    /** {@link DecisionRequest#context()}에 실려 온 신호를 복원한다. 없거나 깨진 값은 중립값으로 폴백. */
    public static RiskSignals fromContext(Map<String, String> context) {
        if (context == null || context.isEmpty()) {
            return none();
        }
        String ip = context.get(CTX_SOURCE_IP);
        String networkIp = context.get(CTX_NETWORK_IP);
        int requests = parseOr(context.get(CTX_REQUESTS_IN_WINDOW), 0);
        Integer hour = parseOrNull(context.get(CTX_HOUR_OF_DAY));
        return new RiskSignals(ip, networkIp, requests, hour);
    }

    private static int parseOr(String value, int fallback) {
        Integer parsed = parseOrNull(value);
        return parsed != null ? parsed : fallback;
    }

    private static Integer parseOrNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
