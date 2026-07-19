package com.ztg.common.risk;

/**
 * 업무시간 판정 — 시(hour)가 {@code [startHour, endHour)} 구간에 들면 업무시간.
 * PDP(payroll 시간 조건)와 PIP(off-hours 가중)가 같은 판정을 이 한 구현으로 공유한다(값 정합은 설정 몫).
 * {@code endHour=24}는 "하루 종일" — 시는 0~23이라 특례 없이 자연 처리된다.
 */
public record BusinessHours(int startHour, int endHour) {

    public BusinessHours {
        if (endHour < startHour) {
            // fail-fast: 끝<시작은 만족 불가능한 구간(항상 업무시간 외) — 기동 시점에 거른다.
            throw new IllegalArgumentException("business-hour-end(%d) must be >= business-hour-start(%d)"
                    .formatted(endHour, startHour));
        }
    }

    /** 이 시(0~23)가 업무시간인가. */
    public boolean contains(int hourOfDay) {
        return hourOfDay >= startHour && hourOfDay < endHour;
    }
}
