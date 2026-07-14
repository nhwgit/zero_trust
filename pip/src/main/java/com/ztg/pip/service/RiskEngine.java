package com.ztg.pip.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;
import com.ztg.pip.store.L4RateFlagStore;

/**
 * 동적 위험 점수 산출기 — 저장 속성(baseline·디바이스) + 휘발성 신호(IP 변화·레이트·시각)를
 * <b>설명 가능한 가중합</b>으로 0~100 점수로 환산한다.
 *
 * <p>순수 함수에 가깝다: 입력(속성·신호·직전 IP)만으로 점수가 결정된다. 상태(직전 IP)는
 * {@link com.ztg.pip.store.SubjectRiskState}가 따로 보관하고, 여기엔 비교 결과만 전달된다 → L2 단위테스트가 쉽다.
 *
 * <p>가중치·임계는 모두 설정으로 뺀다(PolicyEngine과 같은 철학): 데모에서 코드 수정 없이
 * "조건을 바꾸면 ALLOW↔DENY가 뒤집힌다"를 보이기 위함. 점수는 {@link RiskAssessment}에서 0~100 clamp.
 */
@Component
public class RiskEngine {

    private final int deviceUntrustedWeight;
    private final int ipChangeWeight;
    private final int rateBurstWeight;
    private final int rateL4Weight;
    private final int offHoursWeight;
    private final int burstThreshold;
    private final int businessHourStart;
    private final int businessHourEnd;

    public RiskEngine(
            @Value("${ztg.pip.risk.device-untrusted-weight:40}") int deviceUntrustedWeight,
            @Value("${ztg.pip.risk.ip-change-weight:30}") int ipChangeWeight,
            @Value("${ztg.pip.risk.rate-burst-weight:40}") int rateBurstWeight,
            @Value("${ztg.pip.risk.rate-l4-weight:40}") int rateL4Weight,
            @Value("${ztg.pip.risk.off-hours-weight:15}") int offHoursWeight,
            @Value("${ztg.pip.risk.burst-threshold:60}") int burstThreshold,
            @Value("${ztg.pip.risk.business-hour-start:9}") int businessHourStart,
            @Value("${ztg.pip.risk.business-hour-end:18}") int businessHourEnd) {
        this.deviceUntrustedWeight = deviceUntrustedWeight;
        this.ipChangeWeight = ipChangeWeight;
        this.rateBurstWeight = rateBurstWeight;
        this.rateL4Weight = rateL4Weight;
        this.offHoursWeight = offHoursWeight;
        this.burstThreshold = burstThreshold;
        this.businessHourStart = businessHourStart;
        this.businessHourEnd = businessHourEnd;
    }

    /**
     * 위험을 평가한다.
     *
     * @param base       PIP 저장 속성(baseline 위험·디바이스 신뢰)
     * @param signals    게이트웨이가 관측한 휘발성 신호(IP·레이트·시각)
     * @param lastSeenIp 이 주체의 직전 관측 IP({@code null}=첫 관측). IP 변화 판정에만 쓴다.
     * @return 점수 + 기여 신호 내역(설명 가능)
     */
    public RiskAssessment assess(SubjectAttributes base, RiskSignals signals, String lastSeenIp) {
        return assess(base, signals, lastSeenIp, null);
    }

    /**
     * 위험을 평가한다 — L4 플래그 포함 버전.
     *
     * @param l4Flag 이 요청의 출발지 IP에 걸린 커널(XDP) L4 레이트 플래그({@code null}=없음/만료 → 무가중)
     */
    public RiskAssessment assess(SubjectAttributes base, RiskSignals signals, String lastSeenIp,
                                 L4RateFlagStore.Flag l4Flag) {
        List<RiskFactor> factors = new ArrayList<>();
        int score = 0;

        // 0) baseline: 주체 기본 신뢰도(alice=10, 미등록=100). 점수의 출발점.
        int baseline = base.riskScore();
        if (baseline > 0) {
            factors.add(new RiskFactor("baseline", baseline,
                    "stored baseline risk for subject " + base.subject()));
            score += baseline;
        }

        // 1) 미신뢰 디바이스: 관리되지 않는 단말 = 정적이지만 위험 가중.
        if (!base.deviceTrusted()) {
            factors.add(new RiskFactor("device-untrusted", deviceUntrustedWeight,
                    "access from an untrusted (unmanaged) device"));
            score += deviceUntrustedWeight;
        }

        // 2) IP 변화: 직전 관측과 다른 출발지 = 이동/탈취 신호. 첫 관측(lastSeenIp=null)은 변화로 보지 않는다.
        String currentIp = signals == null ? null : signals.sourceIp();
        if (currentIp != null && lastSeenIp != null && !currentIp.equals(lastSeenIp)) {
            factors.add(new RiskFactor("ip-change", ipChangeWeight,
                    "source ip changed %s -> %s".formatted(lastSeenIp, currentIp)));
            score += ipChangeWeight;
        }

        // 3) 레이트 급증: 윈도우 내 요청수가 임계 초과 = 폭주/스크래핑 신호.
        int requests = signals == null ? 0 : signals.requestsInWindow();
        if (requests > burstThreshold) {
            factors.add(new RiskFactor("rate-burst", rateBurstWeight,
                    "%d requests in window exceed burst threshold %d".formatted(requests, burstThreshold)));
            score += rateBurstWeight;
        }

        // 3b) 커널(XDP) L4 레이트 플래그: 스택 진입 전 SYN 레이트 초과가 이 출발지에 보고됨(신호 타입 rate.l4).
        //     3)의 rate-burst(rate.l7)와 관측축이 다르다 — L7은 "인증된 요청 수", L4는 "연결 시도 수"라
        //     토큰 없는 플러드는 L4만 잡는다. 같은 관측의 이중 가산을 막으려 타입을 분리했고,
        //     둘이 동시에 켜지면 각각 가산되는 것은 의도다(서로 다른 증거의 합산).
        if (l4Flag != null) {
            factors.add(new RiskFactor("rate-l4", rateL4Weight,
                    "kernel(XDP) observed %d SYNs in %ds window from %s"
                            .formatted(l4Flag.synsInWindow(), l4Flag.windowSeconds(), l4Flag.sourceIp())));
            score += rateL4Weight;
        }

        // 4) 업무시간 외: 비정상 시각 접근.
        int hour = signals == null ? 12 : signals.hourOfDay();
        if (!withinBusinessHours(hour)) {
            factors.add(new RiskFactor("off-hours", offHoursWeight,
                    "access at hour %02d outside business hours %02d-%02d"
                            .formatted(hour, businessHourStart, businessHourEnd)));
            score += offHoursWeight;
        }

        // RiskAssessment 생성자가 0~100으로 clamp 한다.
        return new RiskAssessment(score, factors);
    }

    private boolean withinBusinessHours(int hour) {
        return hour >= businessHourStart && hour < businessHourEnd;
    }
}
