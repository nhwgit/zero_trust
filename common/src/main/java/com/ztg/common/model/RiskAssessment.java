package com.ztg.common.model;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 주체의 위험 평가 결과 — 0~100 점수 + 그 점수를 만든 기여 신호 목록.
 * PIP가 산출하고 PDP가 임계값을 적용한다.
 *
 * @param score 위험 점수(0~100, 높을수록 위험). 생성 시 범위로 clamp 된다.
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
                .collect(Collectors.joining("; "));
    }
}
