package com.ztg.common.risk;

/**
 * 폭주 밴드 히스테리시스(이중 임계) 판정 — 진입은 {@code requests > enterThreshold},
 * 해제는 {@code requests <= exitThreshold}, 사이 구간은 직전 밴드 유지.
 *
 * <p>게이트웨이(캐시 바이패스)와 PIP(rate-burst 가중)가 같은 판정을 이 한 구현으로 공유한다
 * (임계값 정합은 배포 설정 몫). 이중 임계인 이유: 경계 진동이 매번 밴드 전이로 판정돼 증폭되는 것을 막는다.
 */
public record BurstBandPolicy(int enterThreshold, int exitThreshold) {

    public BurstBandPolicy {
        if (exitThreshold > enterThreshold) {
            // fail-fast: 해제>진입 오설정은 히스테리시스를 뒤집으므로 기동 시점에 거른다.
            throw new IllegalArgumentException("burst-exit-threshold(%d) must be <= burst-threshold(%d)"
                    .formatted(exitThreshold, enterThreshold));
        }
    }

    /** 이번 관측의 폭주 밴드를 판정한다. 순수 함수 — 직전 밴드는 인자로 받는다({@code null}=첫 관측). */
    public boolean judge(int requestsInWindow, Boolean priorBand) {
        if (requestsInWindow > enterThreshold) {
            return true;
        }
        // 사이 구간(exit < r <= enter): 직전 밴드 유지. 해제 임계 이하: 폭주 아님.
        return Boolean.TRUE.equals(priorBand) && requestsInWindow > exitThreshold;
    }
}
