package com.ztg.pip.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;
import com.ztg.common.risk.BurstBandPolicy;
import com.ztg.common.risk.BusinessHours;
import com.ztg.pip.store.L4RateFlagStore;

/**
 * 동적 위험 점수 산출기 — 저장 속성 + 휘발성 신호를 설명 가능한 가중합으로 0~100 점수로 환산한다.
 * 순수 함수에 가깝다: 상태(직전 IP·밴드·hold)는 {@link com.ztg.pip.store.SubjectRiskState}가 보관하고
 * 여기엔 비교 결과만 인자로 들어온다. 가중치·임계는 전부 설정({@link RiskProperties}).
 */
@Component
public class RiskEngine {

    private final int deviceUntrustedWeight;
    private final int ipChangeWeight;
    private final int rateBurstWeight;
    private final int rateL4Weight;
    private final int offHoursWeight;
    private final BurstBandPolicy burstBandPolicy;
    private final BusinessHours businessHours;

    public RiskEngine(RiskProperties props) {
        this.deviceUntrustedWeight = props.deviceUntrustedWeight();
        this.ipChangeWeight = props.ipChangeWeight();
        this.rateBurstWeight = props.rateBurstWeight();
        this.rateL4Weight = props.rateL4Weight();
        this.offHoursWeight = props.offHoursWeight();
        // 오설정은 각 policy record 생성자가 기동 시점에 fail-fast로 거른다.
        this.burstBandPolicy = new BurstBandPolicy(props.burstThreshold(), props.burstExitThreshold());
        // PDP payroll 시간 조건과 공유 구현 — 두 곳의 업무시간 판정이 어긋나지 않게 한다.
        this.businessHours = new BusinessHours(props.businessHourStart(), props.businessHourEnd());
    }

    /**
     * @param base           PIP 저장 속성(baseline 위험·디바이스 신뢰)
     * @param signals        게이트웨이 관측 휘발성 신호({@code null}=중립값, 부재는 무가중)
     * @param lastSeenIp     직전 관측 IP({@code null}=첫 관측 → 변화 아님)
     * @param ipChangeHeld   IP 변화 hold 유효 여부(변화 순간이 지나도 창 동안 가중 유지)
     * @param priorBurstBand 직전 폭주 밴드({@code null}=첫 관측) — 히스테리시스 판정 기준
     * @param l4Flag         커널(XDP) L4 레이트 플래그({@code null}=없음/만료 → 무가중)
     */
    public RiskAssessment assess(SubjectAttributes base, RiskSignals signals, String lastSeenIp,
                                 boolean ipChangeHeld, Boolean priorBurstBand, L4RateFlagStore.Flag l4Flag) {
        RiskSignals sig = signals == null ? RiskSignals.none() : signals;
        List<RiskFactor> factors = new ArrayList<>();
        int score = 0;

        int baseline = base.riskScore();
        if (baseline > 0) {
            factors.add(new RiskFactor("baseline", baseline,
                    "stored baseline risk for subject " + base.subject()));
            score += baseline;
        }

        if (!base.deviceTrusted()) {
            factors.add(new RiskFactor("device-untrusted", deviceUntrustedWeight,
                    "access from an untrusted (unmanaged) device"));
            score += deviceUntrustedWeight;
        }

        // ip-change: 변화 순간 + hold 창 동안 같은 신호명·가중치 유지 — 점수가 창 안에서 안정되어
        // epoch가 출렁이지 않는다(rate-burst 히스테리시스와 같은 원리).
        String currentIp = sig.sourceIp();
        boolean changedNow = currentIp != null && lastSeenIp != null && !currentIp.equals(lastSeenIp);
        if (changedNow || ipChangeHeld) {
            String reason = changedNow
                    ? "source ip changed %s -> %s".formatted(lastSeenIp, currentIp)
                    : "source ip changed recently (within hold window)";
            factors.add(new RiskFactor("ip-change", ipChangeWeight, reason));
            score += ipChangeWeight;
        }

        int requests = sig.requestsInWindow();
        if (burstBand(requests, priorBurstBand)) {
            String reason = requests > burstBandPolicy.enterThreshold()
                    ? "%d requests in window exceed burst threshold %d"
                            .formatted(requests, burstBandPolicy.enterThreshold())
                    : "%d requests in window hold burst band (above exit threshold %d)"
                            .formatted(requests, burstBandPolicy.exitThreshold());
            factors.add(new RiskFactor("rate-burst", rateBurstWeight, reason));
            score += rateBurstWeight;
        }

        // rate-l4: 관측축이 rate-burst(L7 요청 수)와 다르다 — 토큰 없는 플러드는 L4만 잡는다.
        // 둘이 동시에 켜지면 각각 가산되는 것은 의도(서로 다른 증거의 합산).
        if (l4Flag != null) {
            factors.add(new RiskFactor("rate-l4", rateL4Weight,
                    "kernel(XDP) observed %d SYNs in %ds window from %s"
                            .formatted(l4Flag.synsInWindow(), l4Flag.windowSeconds(), l4Flag.sourceIp())));
            score += rateL4Weight;
        }

        int hour = sig.hourOfDay();
        if (!businessHours.contains(hour)) {
            factors.add(new RiskFactor("off-hours", offHoursWeight,
                    "access at hour %02d outside business hours %02d-%02d"
                            .formatted(hour, businessHours.startHour(), businessHours.endHour())));
            score += offHoursWeight;
        }

        // RiskAssessment 생성자가 0~100으로 clamp 한다.
        return new RiskAssessment(score, factors);
    }

    /**
     * 폭주 밴드 히스테리시스 판정: 진입은 {@code burst-threshold} 초과, 해제는 {@code burst-exit-threshold}
     * 이하, 사이 구간은 직전 밴드 유지 — 경계 진동이 매번 epoch bump로 증폭되는 것을 막는다.
     * 게이트웨이 바이패스 트리거와 {@link BurstBandPolicy} 한 벌을 공유한다(로직 드리프트 방지).
     */
    public boolean burstBand(int requestsInWindow, Boolean priorBurstBand) {
        return burstBandPolicy.judge(requestsInWindow, priorBurstBand);
    }
}
