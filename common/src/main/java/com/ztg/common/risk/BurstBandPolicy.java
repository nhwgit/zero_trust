package com.ztg.common.risk;

/**
 * 폭주 밴드 히스테리시스(이중 임계) 판정 — <b>진입</b>은 {@code requests > enterThreshold},
 * <b>해제</b>는 {@code requests <= exitThreshold}, 사이 구간은 직전 밴드 유지.
 *
 * <p>게이트웨이(캐시 바이패스 트리거)와 PIP(rate-burst 가중)가 <b>같은 판정을 이 한 구현으로</b> 공유한다.
 * 두 곳의 판정이 어긋나면 게이트웨이가 전이로 판정한 재평가가 PIP에서 점수 변화로 이어지지 않는
 * "빈 재평가" 구간이 생긴다 — 로직 드리프트는 여기서 구조적으로 막고, <b>임계값 정합</b>(양쪽 설정을
 * 같은 값으로)은 배포 설정의 몫으로 남는다(기본값은 양쪽 다 진입 60/해제 40).
 *
 * <p>단일 임계가 아니라 이중 임계인 이유: 레이트가 임계 경계에서 진동하면 매 진동이 밴드 전이로 판정돼
 * 게이트웨이는 바이패스 반복(엣지 트리거의 레벨 트리거 퇴화), PIP는 점수 ±가중 출렁임 → epoch bump →
 * 전 노드 캐시 무효화로 증폭된다. 사이 구간에서 직전 밴드를 유지하면 경계 진동이 전이가 아니게 된다.
 */
public record BurstBandPolicy(int enterThreshold, int exitThreshold) {

    public BurstBandPolicy {
        if (exitThreshold > enterThreshold) {
            // 해제 임계가 진입 임계보다 높으면 히스테리시스가 뒤집힌다(진입 즉시 해제) — 기동 시 fail-fast.
            throw new IllegalArgumentException("burst-exit-threshold(%d) must be <= burst-threshold(%d)"
                    .formatted(exitThreshold, enterThreshold));
        }
    }

    /**
     * 이번 관측의 폭주 밴드를 판정한다. 순수 함수 — 직전 밴드는 인자로 받는다
     * ({@code null}=첫 관측 → 유지할 밴드가 없으므로 진입 임계만 적용).
     */
    public boolean judge(int requestsInWindow, Boolean priorBand) {
        if (requestsInWindow > enterThreshold) {
            return true;                                       // 진입 임계 초과: 무조건 폭주
        }
        // 사이 구간(exit < r <= enter): 직전 밴드 유지. 해제 임계 이하: 폭주 아님.
        return Boolean.TRUE.equals(priorBand) && requestsInWindow > exitThreshold;
    }
}
