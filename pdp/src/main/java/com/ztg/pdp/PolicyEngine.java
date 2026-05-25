package com.ztg.pdp;

import java.time.Clock;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.SubjectAttributes;

/**
 * ABAC 정책 엔진 — 요청 + 주체 속성 + 시각을 받아 ALLOW/DENY를 판단한다.
 *
 * <p>평가 모델은 <b>deny-overrides</b>: 어느 정책이든 하나라도 DENY면 최종 DENY다.
 * 정책 순서:
 * <ol>
 *   <li><b>위험적응</b>: 위험점수가 임계치 이상이면 리소스 무관하게 DENY.</li>
 *   <li><b>payroll 정책</b>: {@code /api/payroll}는 finance 부서 + 업무시간 + 신뢰 디바이스에서만 허용.</li>
 *   <li><b>기본 허용</b>: 명시적 정책이 없는 리소스는 ALLOW(인증은 이미 게이트웨이에서 통과).</li>
 * </ol>
 *
 * <p>설계 메모: 시각은 {@link Clock}로 주입한다(테스트에서 고정 가능). 업무시간/위험임계치는
 * 설정으로 뺀다 — 완료 기준("조건을 바꾸면 결과가 ALLOW↔DENY로 바뀐다")을 코드 수정 없이 시연하기 위함.
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

    public DecisionResponse evaluate(DecisionRequest request, SubjectAttributes attrs) {
        // 1) 위험적응: 위험점수가 임계치를 넘으면 어떤 리소스든 차단.
        if (attrs.riskScore() >= riskThreshold) {
            return DecisionResponse.deny(
                    "risk score %d >= threshold %d".formatted(attrs.riskScore(), riskThreshold));
        }

        // 2) payroll: 부서/업무시간/디바이스 조건을 모두 만족해야 허용.
        if (request.resource() != null && request.resource().startsWith(PAYROLL_PREFIX)) {
            return evaluatePayroll(attrs);
        }

        // 3) 기본 허용.
        return DecisionResponse.allow("no policy restricts %s; allowed by default".formatted(request.resource()));
    }

    private DecisionResponse evaluatePayroll(SubjectAttributes attrs) {
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
            return DecisionResponse.allow("payroll access granted (finance, business hours, trusted device)");
        }
        return DecisionResponse.deny("payroll denied: " + String.join("; ", failures));
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
