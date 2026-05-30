package com.ztg.common.model;

import java.util.List;

/**
 * 주체의 위험 평가 결과 — 0~100 점수 + 그 점수를 만든 기여 신호 목록.
 *
 * <p>PIP가 산출(information point)하고 PDP가 임계값을 적용(decision point)한다.
 * {@code factors}는 점수의 "내역서"라서, PDP가 DENY할 때 reason에 그대로 붙여 설명 가능한 거부를 만든다.
 *
 * @param score   위험 점수(0~100, 높을수록 위험). 생성 시 범위로 clamp 된다.
 * @param factors 점수에 기여한 신호들(설명용). 비어 있을 수 있다(= 위험 신호 없음).
 */
public record RiskAssessment(int score, List<RiskFactor> factors) {

    public RiskAssessment {
        score = Math.max(0, Math.min(100, score));
        factors = factors == null ? List.of() : List.copyOf(factors);
    }

    /** 기여 신호들을 "signal(+points): detail" 형태로 이어붙인 설명 문자열(거부 reason용). */
    public String explain() {
        if (factors.isEmpty()) {
            return "no risk signals";
        }
        return factors.stream()
                .map(f -> "%s(+%d): %s".formatted(f.signal(), f.points(), f.detail()))
                .reduce((a, b) -> a + "; " + b)
                .orElse("");
    }
}
