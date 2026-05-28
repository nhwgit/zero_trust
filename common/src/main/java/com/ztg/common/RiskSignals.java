package com.ztg.common;

/**
 * 게이트웨이(PEP)가 관측해 전달하는 <b>휘발성</b> 위험 신호. 요청마다 달라진다.
 *
 * <p>저장 속성({@link SubjectAttributes}: 부서/디바이스/baseline)과 달리, 이 값들은 "지금 이 요청"의
 * 맥락이다. 게이트웨이는 모든 요청(캐시 히트 포함)을 보므로 레이트/IP의 권위 있는 관측자다(README 결정 #3).
 *
 * @param sourceIp         이번 요청의 출발지 IP(직전 관측과 비교해 IP 변화 신호 산출)
 * @param requestsInWindow 슬라이딩 윈도우 동안 이 주체의 요청 수(레이트 급증 신호)
 * @param hourOfDay        요청 시각의 시(0~23, 업무시간 외 신호)
 */
public record RiskSignals(String sourceIp, int requestsInWindow, int hourOfDay) {

    /** 신호가 없을 때의 중립값(IP 미상·레이트 0·시각 정오). 테스트/기본 경로용. */
    public static RiskSignals none() {
        return new RiskSignals(null, 0, 12);
    }
}
