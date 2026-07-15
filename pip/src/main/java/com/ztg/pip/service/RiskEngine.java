package com.ztg.pip.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.RiskFactor;
import com.ztg.common.model.RiskSignals;
import com.ztg.common.model.SubjectAttributes;
import com.ztg.common.risk.BurstBandPolicy;
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
 *
 * <p><b>rate-burst는 히스테리시스(이중 임계)로 판정한다</b>({@link #burstBand}): 진입은 {@code burst-threshold}
 * 초과, 해제는 {@code burst-exit-threshold} 이하. 단일 임계면 레이트가 경계에서 진동할 때 점수가 ±가중치로
 * 함께 출렁여 <b>매 진동이 epoch bump → fan-out → 전 노드 캐시 무효화</b>로 증폭된다(계단 함수의 경계 진동).
 * 판정 구현은 게이트웨이의 바이패스 트리거와 {@link BurstBandPolicy} <b>한 벌을 공유</b>한다(로직 드리프트 방지
 * — 임계값 정합은 배포 설정의 몫). 직전 밴드는 {@link com.ztg.pip.store.SubjectRiskState}가 기억하고 여기엔
 * 비교 기준으로만 들어온다 — 직전 IP({@code lastSeenIp})와 같은 패턴으로, 엔진의 순수성(입력만으로 결정)은 유지된다.
 *
 * <p><b>ip-change는 hold 창으로 판정한다</b>: 변화 관측 순간뿐 아니라 hold({@code ip-change-hold}) 동안
 * 가중을 유지한다({@code ipChangeHeld}). 순간 신호면 바뀐 그 평가 다음의 재평가에서 바로 빠져 — 탈취
 * 시나리오의 DENY가 고위험 TTL(~1s)짜리 스파이크가 되어 재시도로 우회되고, 그 짧은 상태는 fan-out을 놓친
 * 노드에 아예 닿지 않는다. hold 판정(시계 비교)은 {@code SubjectRiskState}가 하고 여기엔 결과만 들어온다.
 */
@Component
public class RiskEngine {

    private final int deviceUntrustedWeight;
    private final int ipChangeWeight;
    private final int rateBurstWeight;
    private final int rateL4Weight;
    private final int offHoursWeight;
    private final BurstBandPolicy burstBandPolicy;
    private final int businessHourStart;
    private final int businessHourEnd;

    public RiskEngine(
            @Value("${ztg.pip.risk.device-untrusted-weight:40}") int deviceUntrustedWeight,
            @Value("${ztg.pip.risk.ip-change-weight:30}") int ipChangeWeight,
            @Value("${ztg.pip.risk.rate-burst-weight:40}") int rateBurstWeight,
            @Value("${ztg.pip.risk.rate-l4-weight:40}") int rateL4Weight,
            @Value("${ztg.pip.risk.off-hours-weight:15}") int offHoursWeight,
            @Value("${ztg.pip.risk.burst-threshold:60}") int burstThreshold,
            @Value("${ztg.pip.risk.burst-exit-threshold:40}") int burstExitThreshold,
            @Value("${ztg.pip.risk.business-hour-start:9}") int businessHourStart,
            @Value("${ztg.pip.risk.business-hour-end:18}") int businessHourEnd) {
        this.deviceUntrustedWeight = deviceUntrustedWeight;
        this.ipChangeWeight = ipChangeWeight;
        this.rateBurstWeight = rateBurstWeight;
        this.rateL4Weight = rateL4Weight;
        this.offHoursWeight = offHoursWeight;
        // 오설정(해제>진입)은 policy 생성자가 기동 시점에 fail-fast로 거른다.
        this.burstBandPolicy = new BurstBandPolicy(burstThreshold, burstExitThreshold);
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
        return assess(base, signals, lastSeenIp, false, null, null);
    }

    /**
     * 위험을 평가한다 — IP 변화 hold·직전 폭주 밴드·L4 플래그 포함 버전.
     *
     * @param ipChangeHeld   이 주체의 IP 변화 hold가 유효한가(= hold 창 안에 IP가 바뀐 적 있음).
     *                       비교 기준({@code lastSeenIp})이 갱신된 뒤에도 ip-change 가중을 창 동안 유지한다.
     * @param priorBurstBand 이 주체의 직전 폭주 밴드({@code null}=첫 관측). rate-burst 히스테리시스 판정에만 쓴다.
     * @param l4Flag         이 요청의 출발지 IP에 걸린 커널(XDP) L4 레이트 플래그({@code null}=없음/만료 → 무가중)
     */
    public RiskAssessment assess(SubjectAttributes base, RiskSignals signals, String lastSeenIp,
                                 boolean ipChangeHeld, Boolean priorBurstBand, L4RateFlagStore.Flag l4Flag) {
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
        //    변화 순간이 지나도 hold 창 동안 같은 신호명·가중치로 유지된다(ipChangeHeld) — 점수가 창 안에서
        //    안정되어 epoch가 출렁이지 않고, 창이 끝날 때 한 번만 하강한다(rate-burst 히스테리시스와 같은 원리).
        String currentIp = signals == null ? null : signals.sourceIp();
        boolean changedNow = currentIp != null && lastSeenIp != null && !currentIp.equals(lastSeenIp);
        if (changedNow || ipChangeHeld) {
            String reason = changedNow
                    ? "source ip changed %s -> %s".formatted(lastSeenIp, currentIp)
                    : "source ip changed recently (within hold window)";
            factors.add(new RiskFactor("ip-change", ipChangeWeight, reason));
            score += ipChangeWeight;
        }

        // 3) 레이트 급증: 폭주 밴드(히스테리시스 판정)면 가중 = 폭주/스크래핑 신호.
        //    임계 사이 구간에서 직전 밴드가 유지될 때도 같은 신호명·가중치라 점수가 안정된다(epoch 출렁임 방지).
        int requests = signals == null ? 0 : signals.requestsInWindow();
        if (burstBand(requests, priorBurstBand)) {
            String reason = requests > burstBandPolicy.enterThreshold()
                    ? "%d requests in window exceed burst threshold %d"
                            .formatted(requests, burstBandPolicy.enterThreshold())
                    : "%d requests in window hold burst band (above exit threshold %d)"
                            .formatted(requests, burstBandPolicy.exitThreshold());
            factors.add(new RiskFactor("rate-burst", rateBurstWeight, reason));
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

    /**
     * 폭주 밴드를 히스테리시스(이중 임계)로 판정한다: <b>진입</b>은 {@code requests > burst-threshold},
     * <b>해제</b>는 {@code requests <= burst-exit-threshold}. 두 임계 사이 구간에선 <b>직전 밴드를 유지</b>해,
     * 레이트가 진입 임계 경계에서 진동해도 밴드(→ rate-burst 가중 → 점수 → epoch)가 함께 출렁이지 않는다.
     *
     * <p>순수 함수 — 직전 밴드는 인자로 받는다({@code null}=첫 관측 → 진입 임계만 적용). 호출자
     * ({@link AssessmentService})가 평가 후 이 판정 결과를 {@code SubjectRiskState}에 기록해 다음 비교 기준으로 쓴다.
     * 판정 자체는 {@link BurstBandPolicy}에 위임 — 게이트웨이의 바이패스 트리거와 같은 구현을 쓴다.
     */
    public boolean burstBand(int requestsInWindow, Boolean priorBurstBand) {
        return burstBandPolicy.judge(requestsInWindow, priorBurstBand);
    }

    private boolean withinBusinessHours(int hour) {
        return hour >= businessHourStart && hour < businessHourEnd;
    }
}
