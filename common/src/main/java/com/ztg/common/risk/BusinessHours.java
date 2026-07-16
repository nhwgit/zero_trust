package com.ztg.common.risk;

/**
 * 업무시간 판정 — 시(hour)가 {@code [startHour, endHour)} 구간에 들면 업무시간.
 *
 * <p>PDP(payroll 시간 조건)와 PIP(off-hours 가중)가 <b>같은 판정을 이 한 구현으로</b> 공유한다.
 * 두 곳의 판정이 어긋나면 "PIP는 업무시간 외로 가중하는데 PDP는 업무시간으로 판정"하는 불일치가 생긴다 —
 * 로직 드리프트는 여기서 구조적으로 막고, <b>값 정합</b>(양쪽 설정을 같은 값으로)은 배포 설정의 몫으로
 * 남긴다({@link BurstBandPolicy}와 같은 원칙, 기본값은 양쪽 다 9-18).
 *
 * <p>{@code endHour=24}는 "자정까지(하루 종일)"를 뜻한다 — 시는 0~23이라 {@code hour < 24}가 항상
 * 참이므로 특례 없이 자연 처리된다(과거 PDP 구현은 {@code LocalTime.of(24,0)} 예외 때문에 분기가 필요했다).
 */
public record BusinessHours(int startHour, int endHour) {

    public BusinessHours {
        if (endHour < startHour) {
            // 끝이 시작보다 앞서면 만족 불가능한 구간(항상 업무시간 외) — 오설정이므로 기동 시 fail-fast.
            throw new IllegalArgumentException("business-hour-end(%d) must be >= business-hour-start(%d)"
                    .formatted(endHour, startHour));
        }
    }

    /** 이 시(0~23)가 업무시간인가. */
    public boolean contains(int hourOfDay) {
        return hourOfDay >= startHour && hourOfDay < endHour;
    }
}
