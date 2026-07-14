package com.ztg.pdp.policy;

import java.time.Clock;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.SubjectAttributes;

/**
 * ABAC 정책 엔진 — 요청 + 주체 속성 + <b>동적 위험 평가</b> + 시각을 받아 ALLOW/DENY를 판단한다.
 *
 * <p>평가 모델은 <b>deny-overrides</b>: 어느 정책이든 하나라도 DENY면 최종 DENY다.
 * 정책 순서:
 * <ol>
 *   <li><b>위험적응</b>: PIP가 산출한 {@link RiskAssessment#score()}가 임계치 이상이면 리소스 무관하게 DENY.</li>
 *   <li><b>payroll 정책</b>: {@code /api/payroll}는 finance 부서 + 업무시간 + 신뢰 디바이스에서만 허용.</li>
 *   <li><b>기본 허용</b>: 명시적 정책이 없는 리소스는 ALLOW(인증은 이미 게이트웨이에서 통과).</li>
 * </ol>
 *
 * <p>설계 메모: 위험 <b>점수 산출은 PIP</b>(정보점), 여기 PDP(결정점)는 <b>임계만</b>
 * 적용한다. 그래서 정적 {@code attrs.riskScore()}가 아니라 동적 {@link RiskAssessment}를 임계와 비교하고,
 * DENY 사유에 {@link RiskAssessment#explain()}(기여 신호 내역)을 그대로 실어 설명 가능한 거부를 만든다.
 * 모든 결정에 위험점수+{@code epoch}를 실어 게이트웨이가 epoch를 학습(능동 무효화)하게 한다.
 *
 * <p>시각은 {@link Clock}로 주입한다(테스트에서 고정 가능). 업무시간/위험임계치는 설정으로 뺀다 —
 * 완료 기준("조건을 바꾸면 결과가 ALLOW↔DENY로 바뀐다")을 코드 수정 없이 시연하기 위함.
 */
@Component
public class PolicyEngine {

    private static final String PAYROLL_PREFIX = "/api/payroll";
    private static final String FINANCE = "finance";

    private final Clock clock;
    private final int businessHourStart;
    private final int businessHourEnd;
    private final int riskThreshold;

    public PolicyEngine(Clock clock,
                        @Value("${ztg.pdp.business-hour-start:9}") int businessHourStart,
                        @Value("${ztg.pdp.business-hour-end:18}") int businessHourEnd,
                        @Value("${ztg.pdp.risk-threshold:80}") int riskThreshold) {
        this.clock = clock;
        this.businessHourStart = businessHourStart;
        this.businessHourEnd = businessHourEnd;
        this.riskThreshold = riskThreshold;
    }

    /**
     * @param request 인가 요청
     * @param attrs   PIP 저장 속성(부서/디바이스) — payroll 정책 입력
     * @param risk    PIP가 산출한 동적 위험 평가 — 위험적응 정책 입력(임계만 여기서 적용)
     * @param epoch   주체의 현재 위험 epoch — 결정에 실어 게이트웨이로 역전파
     */
    public DecisionResponse evaluate(DecisionRequest request, SubjectAttributes attrs,
                                     RiskAssessment risk, long epoch) {
        // 1) 위험적응: PIP가 낸 동적 점수가 임계치를 넘으면 어떤 리소스든 차단(사유=점수 내역).
        if (risk.score() >= riskThreshold) {
            return DecisionResponse.deny(
                    "risk score %d >= threshold %d [%s]".formatted(risk.score(), riskThreshold, risk.explain()),
                    risk, epoch);
        }

        // 2) payroll: 부서/업무시간/디바이스 조건을 모두 만족해야 허용.
        if (request.resource() != null && request.resource().startsWith(PAYROLL_PREFIX)) {
            return evaluatePayroll(attrs, risk, epoch);
        }

        // 3) 기본 허용.
        return DecisionResponse.allow(
                "no policy restricts %s; allowed by default".formatted(request.resource()), risk, epoch);
    }

    private DecisionResponse evaluatePayroll(SubjectAttributes attrs, RiskAssessment risk, long epoch) {
        List<String> failures = new ArrayList<>();

        if (!FINANCE.equalsIgnoreCase(attrs.department())) {
            failures.add("department must be finance (was %s)".formatted(attrs.department()));
        }
        LocalTime now = LocalTime.now(clock);
        if (!withinBusinessHours(now)) {
            failures.add("must be within business hours %02d-%02d (was %s)"
                    .formatted(businessHourStart, businessHourEnd, now.withNano(0)));
        }
        if (!attrs.deviceTrusted()) {
            failures.add("device must be trusted (was untrusted)");
        }

        if (failures.isEmpty()) {
            return DecisionResponse.allow(
                    "payroll access granted (finance, business hours, trusted device)", risk, epoch);
        }
        return DecisionResponse.deny("payroll denied: " + String.join("; ", failures), risk, epoch);
    }

    private boolean withinBusinessHours(LocalTime now) {
        if (now.isBefore(LocalTime.of(businessHourStart, 0))) {
            return false;
        }
        // end=24는 "자정까지(하루 종일)"를 뜻한다. LocalTime.of(24,0)은 DateTimeException이므로 분리 처리.
        if (businessHourEnd >= 24) {
            return true;
        }
        return now.isBefore(LocalTime.of(businessHourEnd, 0));
    }
}
