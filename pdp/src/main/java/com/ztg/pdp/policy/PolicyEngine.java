package com.ztg.pdp.policy;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.model.RiskAssessment;
import com.ztg.common.model.SubjectAttributes;
import com.ztg.common.risk.BusinessHours;

/**
 * ABAC 정책 엔진 — deny-overrides로 위험적응(점수 임계) → payroll(부서+업무시간+신뢰 디바이스) →
 * 기본 허용 순으로 평가한다.
 *
 * <p>점수 산출은 PIP 몫, 여기서는 임계만 적용한다. 시각도 자체 시계가 아니라 게이트웨이가 관측해
 * 실은 hour-of-day를 쓴다 — 판정 입력의 관측 지점을 단일화해 노드별 TZ에 판정이 흔들리지 않게 한다.
 * 모든 결정에 위험점수+{@code epoch}를 실어 게이트웨이가 epoch를 학습(능동 무효화)하게 한다.
 */
@Component
public class PolicyEngine {

    private static final String PAYROLL_PREFIX = "/api/payroll";
    private static final String FINANCE = "finance";

    private final BusinessHours businessHours;
    private final int riskThreshold;

    public PolicyEngine(@Value("${ztg.pdp.business-hour-start:9}") int businessHourStart,
                        @Value("${ztg.pdp.business-hour-end:18}") int businessHourEnd,
                        @Value("${ztg.pdp.risk-threshold:80}") int riskThreshold) {
        // PIP off-hours 판정과 공유 구현(BusinessHours) — 두 곳의 업무시간 판정이 어긋나지 않게 한다.
        this.businessHours = new BusinessHours(businessHourStart, businessHourEnd);
        this.riskThreshold = riskThreshold;
    }

    /**
     * @param epoch     주체의 현재 위험 epoch — 결정에 실어 게이트웨이로 역전파
     * @param hourOfDay 게이트웨이가 관측한 요청 시각(0~23) — PIP off-hours 가중과 같은 값.
     *                  {@code null}=미관측 — 시간 조건은 경성 조건이라 검증 불가 = 불만족(fail-close)
     */
    public DecisionResponse evaluate(DecisionRequest request, SubjectAttributes attrs,
                                     RiskAssessment risk, long epoch, Integer hourOfDay) {
        if (risk.score() >= riskThreshold) {
            return DecisionResponse.deny(
                    "risk score %d >= threshold %d [%s]".formatted(risk.score(), riskThreshold, risk.explain()),
                    risk, epoch);
        }

        if (request.resource() != null && request.resource().startsWith(PAYROLL_PREFIX)) {
            return evaluatePayroll(attrs, risk, epoch, hourOfDay);
        }

        return DecisionResponse.allow(
                "no policy restricts %s; allowed by default".formatted(request.resource()), risk, epoch);
    }

    private DecisionResponse evaluatePayroll(SubjectAttributes attrs, RiskAssessment risk,
                                             long epoch, Integer hourOfDay) {
        List<String> failures = new ArrayList<>();

        if (!FINANCE.equalsIgnoreCase(attrs.department())) {
            failures.add("department must be finance (was %s)".formatted(attrs.department()));
        }
        if (hourOfDay == null) {
            failures.add("must be within business hours %02d-%02d (hour unobserved)"
                    .formatted(businessHours.startHour(), businessHours.endHour()));
        } else if (!businessHours.contains(hourOfDay)) {
            failures.add("must be within business hours %02d-%02d (was hour %02d)"
                    .formatted(businessHours.startHour(), businessHours.endHour(), hourOfDay));
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
}
