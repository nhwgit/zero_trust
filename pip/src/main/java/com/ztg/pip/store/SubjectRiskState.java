package com.ztg.pip.store;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 주체별 지속 위험 맥락 — 직전 IP(논리·네트워크 두 축) + ip-change hold + epoch + 직전 점수·팩터 + 직전 폭주 밴드.
 *
 * <p>논리 축({@code lastSeenIp})은 ip-change 판정 기준, 네트워크 축({@code lastNetworkIp})은
 * 커널(XDP) L4 신호↔주체 번역 기준. epoch는 위험 점수/팩터 구성이 변할 때 +1 되는 능동 무효화 토큰이다.
 * in-memory(단일 PIP).
 */
@Component
public class SubjectRiskState {

    /**
     * 주체별 스냅샷(불변). {@code null} 필드 = 미관측. 필드 하나만 바꾼 새 스냅샷은 {@code with*}로 만들어
     * 위치 기반 생성자 호출(필드 순서 실수)을 이 record 안에 가둔다.
     */
    private record State(String lastSeenIp, String lastNetworkIp, long epoch, Integer lastScore,
                         Set<String> lastFactors, Boolean lastBurstBand, Long ipChangeHoldUntilNanos) {

        static final State EMPTY = new State(null, null, 0L, null, null, null, null);

        State withIps(String ip, String networkIp, Long holdUntilNanos) {
            return new State(ip, networkIp, epoch, lastScore, lastFactors, lastBurstBand, holdUntilNanos);
        }

        State withScore(int score, Set<String> factors, boolean bump) {
            return new State(lastSeenIp, lastNetworkIp, bump ? epoch + 1 : epoch, score, factors,
                    lastBurstBand, ipChangeHoldUntilNanos);
        }

        State withBand(boolean band) {
            return new State(lastSeenIp, lastNetworkIp, epoch, lastScore, lastFactors, band,
                    ipChangeHoldUntilNanos);
        }

        /** 맥락을 비우되 epoch는 보존 — 게이트웨이 epoch 학습이 단조(max)라 되돌리면 영구 캐시 미스가 된다. */
        State resetKeepingEpoch() {
            return new State(null, null, epoch, null, null, null, null);
        }
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final long ipChangeHoldNanos;
    private final LongSupplier nanoClock;

    @Autowired
    public SubjectRiskState(@Value("${ztg.pip.risk.ip-change-hold:30s}") Duration ipChangeHold) {
        this(ipChangeHold, System::nanoTime);
    }

    /** 테스트용 — 단조 시계 주입으로 hold 만료를 결정적으로 검증한다. */
    public SubjectRiskState(Duration ipChangeHold, LongSupplier nanoClock) {
        this.ipChangeHoldNanos = ipChangeHold.toNanos();
        this.nanoClock = nanoClock;
    }

    /** 직전 관측 IP(논리 축). {@code null}=첫 관측(변화로 치지 않음). */
    public String lastSeenIp(String subject) {
        State s = states.get(subject);
        return s == null ? null : s.lastSeenIp();
    }

    /**
     * 이번 관측의 IP를 두 축 모두 원자적으로 기록한다(한 축만 갱신하는 반쪽 상태 방지).
     * 논리 축이 직전과 다르면 hold를 시작/연장한다(첫 관측은 변화 아님). 네트워크 축은 변화 판정이 없다
     * (네트워크 경로 변경은 위험 신호가 아니라 관측 좌표의 이동). 각 축의 null/blank는 기준을 덮지 않는다.
     */
    public void recordIps(String subject, String sourceIp, String networkIp) {
        boolean hasSource = sourceIp != null && !sourceIp.isBlank();
        boolean hasNetwork = networkIp != null && !networkIp.isBlank();
        if (!hasSource && !hasNetwork) {
            return;
        }
        states.compute(subject, (k, s) -> {
            State cur = s == null ? State.EMPTY : s;
            String nextIp = hasSource ? sourceIp : cur.lastSeenIp();
            String nextNetworkIp = hasNetwork ? networkIp : cur.lastNetworkIp();
            boolean changed = hasSource && cur.lastSeenIp() != null && !sourceIp.equals(cur.lastSeenIp());
            // 양쪽 다 Long으로 박싱 — long/Long 혼합 삼항은 null 쪽을 언박싱해 NPE가 난다.
            Long holdUntil = changed
                    ? Long.valueOf(nanoClock.getAsLong() + ipChangeHoldNanos)
                    : cur.ipChangeHoldUntilNanos();
            return cur.withIps(nextIp, nextNetworkIp, holdUntil);
        });
    }

    /** IP 변화 hold가 아직 유효한가(= hold 창 안에 논리 축 IP가 바뀐 적 있는가). */
    public boolean ipChangeHeld(String subject) {
        State s = states.get(subject);
        Long holdUntil = s == null ? null : s.ipChangeHoldUntilNanos();
        // 차이로 비교해 nanoTime 래핑에 안전. 만료 엔트리는 지우지 않는다(주체당 1건, 다음 변화가 덮는다).
        return holdUntil != null && nanoClock.getAsLong() - holdUntil < 0;
    }

    /** 주체의 현재 epoch(없으면 0). */
    public long currentEpoch(String subject) {
        State s = states.get(subject);
        return s == null ? 0L : s.epoch();
    }

    /**
     * 이번 점수·기여 팩터 구성을 반영하고 현재 epoch를 반환한다. 점수 또는 팩터 이름 집합이 직전과
     * 달라졌을 때만 +1(능동 무효화) — 팩터 집합도 보는 이유는 등가중 팩터 교체(rate-burst↔rate-l4)가
     * 점수 동률이라 점수만으론 위험의 성격 변화를 놓치기 때문. 첫 관측은 기준 설정이라 bump 없음.
     */
    public long recordScore(String subject, int score, Set<String> factorNames) {
        Set<String> factors = factorNames == null ? Set.of() : Set.copyOf(factorNames);
        State updated = states.compute(subject, (k, s) -> {
            State cur = s == null ? State.EMPTY : s;
            boolean bump = cur.lastScore() != null
                    && (cur.lastScore() != score || !factors.equals(cur.lastFactors()));
            return cur.withScore(score, factors, bump);
        });
        return updated.epoch();
    }

    /** 직전 폭주 밴드({@code null}=첫 관측 → 히스테리시스 없이 진입 임계만 적용). */
    public Boolean lastBurstBand(String subject) {
        State s = states.get(subject);
        return s == null ? null : s.lastBurstBand();
    }

    /** 이번 폭주 밴드를 기록한다(다음 평가의 히스테리시스 기준). */
    public void recordBurstBand(String subject, boolean band) {
        states.compute(subject, (k, s) -> (s == null ? State.EMPTY : s).withBand(band));
    }

    /**
     * 직전 관측의 네트워크 축 IP가 {@code networkIp}인 주체들 — L4 신호는 패킷 소스 IP 단위라
     * 같은 좌표계로만 번역된다(논리 축으로 맞추면 LB 뒤에서 항상 실패). 전수 순회지만 주체 수는
     * 세션 규모라 충분하다(역인덱스는 필요해질 때).
     */
    public List<String> subjectsByNetworkIp(String networkIp) {
        if (networkIp == null || networkIp.isBlank()) {
            return List.of();
        }
        return states.entrySet().stream()
                .filter(e -> networkIp.equals(e.getValue().lastNetworkIp()))
                .map(Map.Entry::getKey)
                .toList();
    }

    /** 데모 리셋: 위험 맥락을 비운다(다음 관측은 첫 관측 취급). epoch만 보존 — {@link State#resetKeepingEpoch}. */
    public void evict(String subject) {
        states.computeIfPresent(subject, (k, s) -> s.resetKeepingEpoch());
    }
}
