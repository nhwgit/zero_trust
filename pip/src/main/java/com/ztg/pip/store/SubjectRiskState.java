package com.ztg.pip.store;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 주체별 <b>지속(stateful)</b> 위험 맥락 — 직전 관측 IP + 능동 무효화 epoch + 직전 위험점수 + 직전 폭주 밴드.
 *
 * <p>IP 변화 신호는 "지금 IP가 직전과 다른가"라 직전 값을 기억해야 한다(휘발성 신호와 달리 상태가 필요).
 * 슬라이딩 윈도우 레이트는 모든 요청을 보는 게이트웨이가 관측하므로 여기 두지 않는다.
 * 폭주 <b>밴드</b>(rate-burst의 히스테리시스 판정 기준)도 "직전에 폭주였나"를 기억해야 하는 같은 부류의 상태다
 * — 레이트가 임계 경계에서 진동할 때 점수(→epoch)가 함께 출렁이지 않게 한다({@link com.ztg.pip.service.RiskEngine#burstBand}).
 *
 * <p><b>epoch(능동 무효화 토큰):</b> 위험 점수가 직전과 달라지면 epoch를 +1 한다.
 * epoch는 결정에 piggyback돼 게이트웨이로 가고, 게이트웨이는 새 epoch를 학습해 옛 캐시를 버린다
 * (캐시 키에 epoch가 포함돼 옛 엔트리는 더는 조회되지 않는다) → 같은 세션에서 <b>재로그인 없이</b>
 * 위험 변화가 ALLOW→DENY로 반영된다.
 *
 * <p>설계 메모: 점수 "변화"를 트리거로 삼아 PIP는 PDP의 임계값을 몰라도 된다(관심사 분리). 같은 점수
 * 반복은 bump하지 않아 안정 상태에선 캐시가 유지된다. {@link #evict}로 데모 리셋(첫 관측 취급).
 * in-memory(단일 PIP) — 다중화는 Redis 등 외부 저장소 확장으로 미룬다.
 */
@Component
public class SubjectRiskState {

    /** 주체별 위험 맥락 스냅샷(불변). {@code lastScore=null}=점수 미관측, {@code lastBurstBand=null}=밴드 미관측. */
    private record State(String lastSeenIp, long epoch, Integer lastScore, Boolean lastBurstBand) {}

    private final Map<String, State> states = new ConcurrentHashMap<>();

    /** 직전 관측 IP를 반환한다(없으면 {@code null} = 첫 관측 → IP 변화로 치지 않음). */
    public String lastSeenIp(String subject) {
        State s = states.get(subject);
        return s == null ? null : s.lastSeenIp();
    }

    /** 이번 관측 IP를 기록한다(다음 요청의 IP 변화 비교 기준). null/blank는 무시(미상 IP는 기준을 덮지 않음). */
    public void recordIp(String subject, String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return;
        }
        states.compute(subject, (k, s) -> s == null
                ? new State(sourceIp, 0L, null, null)
                : new State(sourceIp, s.epoch(), s.lastScore(), s.lastBurstBand()));
    }

    /** 주체의 현재 epoch(없으면 0). 캐시 키/검증용 조회. */
    public long currentEpoch(String subject) {
        State s = states.get(subject);
        return s == null ? 0L : s.epoch();
    }

    /**
     * 이번 위험 점수를 반영하고 현재 epoch를 반환한다. 점수가 직전과 <b>달라졌을 때만</b> epoch를 +1 한다
     * (능동 무효화). 첫 관측은 bump 없이 점수만 기록(epoch 0)한다 — 변화가 아니라 기준 설정이므로.
     *
     * @param subject 대상 주체
     * @param score   이번에 산출된 위험 점수(0~100)
     * @return 반영 후 주체의 현재 epoch
     */
    public long recordScore(String subject, int score) {
        State updated = states.compute(subject, (k, s) -> {
            if (s == null) {
                return new State(null, 0L, score, null);                                       // 첫 관측: 기준 설정, bump 없음
            }
            if (s.lastScore() == null || s.lastScore() == score) {
                return new State(s.lastSeenIp(), s.epoch(), score, s.lastBurstBand());         // 변화 없음: epoch 유지
            }
            return new State(s.lastSeenIp(), s.epoch() + 1, score, s.lastBurstBand());         // 위험 변화: 능동 무효화 bump
        });
        return updated.epoch();
    }

    /** 직전 폭주 밴드를 반환한다({@code null}=첫 관측 → 히스테리시스 유지 없이 진입 임계만 적용). */
    public Boolean lastBurstBand(String subject) {
        State s = states.get(subject);
        return s == null ? null : s.lastBurstBand();
    }

    /** 이번 폭주 밴드를 기록한다(다음 평가의 히스테리시스 판정 기준). */
    public void recordBurstBand(String subject, boolean band) {
        states.compute(subject, (k, s) -> s == null
                ? new State(null, 0L, null, band)
                : new State(s.lastSeenIp(), s.epoch(), s.lastScore(), band));
    }

    /**
     * 직전 관측 IP가 {@code sourceIp}인 주체들을 찾는다 — 커널(XDP) L4 신호는 IP 단위로 도착하므로,
     * 그 IP를 "지금 쓰고 있는" 주체로 번역해야 재평가(epoch bump → 능동 무효화)를 걸 수 있다.
     * 전수 순회지만 주체 수는 세션 수 규모라 데모/단일 PIP에선 충분하다(역인덱스는 필요해질 때).
     */
    public List<String> subjectsByLastSeenIp(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return List.of();
        }
        return states.entrySet().stream()
                .filter(e -> sourceIp.equals(e.getValue().lastSeenIp()))
                .map(Map.Entry::getKey)
                .toList();
    }

    /** 데모 리셋: 주체의 위험 상태를 비운다(다음 관측은 첫 관측으로 취급, epoch 0부터). */
    public void evict(String subject) {
        states.remove(subject);
    }
}
