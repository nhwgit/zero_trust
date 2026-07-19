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
 * 주체별 <b>지속(stateful)</b> 위험 맥락 — 직전 관측 IP(논리·네트워크 두 축) + IP 변화 hold + 능동 무효화 epoch + 직전 위험점수 + 직전 폭주 밴드.
 *
 * <p><b>IP는 두 축으로 기억한다:</b> 논리 축({@code lastSeenIp}, 신뢰 프록시 XFF 반영)은 ip-change 판정의
 * 비교 기준이고, 네트워크 축({@code lastNetworkIp}, 게이트웨이 소켓 피어)은 커널(XDP) L4 신호↔주체 번역의
 * 매칭 기준이다 — LB/프록시 뒤에선 두 좌표가 달라, 한 축으로 겸하면 번역이 깨진다({@link #subjectsByNetworkIp}).
 *
 * <p>IP 변화 신호는 "지금 IP가 직전과 다른가"라 직전 값을 기억해야 한다(휘발성 신호와 달리 상태가 필요).
 * 슬라이딩 윈도우 레이트는 모든 요청을 보는 게이트웨이가 관측하므로 여기 두지 않는다.
 * 폭주 <b>밴드</b>(rate-burst의 히스테리시스 판정 기준)도 "직전에 폭주였나"를 기억해야 하는 같은 부류의 상태다
 * — 레이트가 임계 경계에서 진동할 때 점수(→epoch)가 함께 출렁이지 않게 한다({@link com.ztg.pip.service.RiskEngine#burstBand}).
 *
 * <p><b>IP 변화 hold({@code ip-change-hold}):</b> 변화를 관측한 순간부터 hold 동안 "최근에 IP가 바뀐 주체"로
 * 기억한다({@link #ipChangeHeld}). 비교 기준({@code lastSeenIp})은 관측마다 덮이므로, hold가 없으면 ip-change
 * 가중이 <b>바뀐 그 한 번의 평가에만</b> 실리고 바로 다음 재평가(고위험 TTL ~1s)에서 빠진다 — 탈취 시나리오의
 * DENY가 1초짜리 스파이크가 되어 재시도로 우회되고, fan-out을 놓친 노드는 그 상태를 아예 못 본다.
 * hold는 신호를 시간 창으로 늘려 이를 막는다. 창이 지나면 자동 소멸(가역성 — {@link L4RateFlagStore}의
 * rate-l4 hold와 같은 논리). 창 안에서 또 바뀌면 만료를 연장한다(회전 = 지속 신호).
 *
 * <p><b>epoch(능동 무효화 토큰):</b> 위험 점수 <b>또는 기여 팩터 구성</b>이 직전과 달라지면 epoch를 +1 한다.
 * epoch는 결정에 piggyback돼 게이트웨이로 가고, 게이트웨이는 새 epoch를 학습해 옛 캐시를 버린다
 * (캐시 키에 epoch가 포함돼 옛 엔트리는 더는 조회되지 않는다) → 같은 세션에서 <b>재로그인 없이</b>
 * 위험 변화가 ALLOW→DENY로 반영된다.
 *
 * <p>설계 메모: 점수 "변화"를 트리거로 삼아 PIP는 PDP의 임계값을 몰라도 된다(관심사 분리). 같은 점수
 * 반복은 bump하지 않아 안정 상태에선 캐시가 유지된다. 팩터 구성을 함께 보는 이유: 가중치가 같은 팩터의
 * 교체(예: rate-burst 40 ↔ rate-l4 40, L4 재평가 경로)는 점수가 동률이라 점수만으론 위험의 <b>성격</b> 변화를
 * 놓친다 — 증거가 바뀌었으면 캐시된 결정도 다시 물어야 한다(팩터 이름 집합 비교, 점수 비교와 OR). {@link #evict}로 데모 리셋 — 단, <b>epoch는 보존</b>한다:
 * 게이트웨이가 epoch를 단조(max)로만 학습하므로 여기서 0으로 되돌리면 게이트웨이는 계속 옛(더 큰) 세대로
 * 조회하고 적재는 새(작은) 세대로 갈려 그 주체가 영구 캐시 미스가 된다. 세대 토큰은 뒤로 가지 않는다.
 * in-memory(단일 PIP) — 다중화는 Redis 등 외부 저장소 확장으로 미룬다.
 */
@Component
public class SubjectRiskState {

    /**
     * 주체별 위험 맥락 스냅샷(불변). {@code lastScore=null}=점수 미관측(이때 {@code lastFactors}도 null),
     * {@code lastBurstBand=null}=밴드 미관측, {@code ipChangeHoldUntilNanos=null}=활성 hold 없음
     * (변화 미관측 또는 만료 후 새 변화 없음), {@code lastNetworkIp=null}=네트워크 축 미관측.
     *
     * <p>필드 하나만 바꾼 새 스냅샷은 {@code with*} 메서드로 만든다 — 위치 기반 {@code new State(...)}를 이
     * record 안에 가둬, 호출부는 "무엇이 바뀌는가"만 드러내고 필드 순서 실수(footgun)를 한 곳으로 모은다.
     */
    private record State(String lastSeenIp, String lastNetworkIp, long epoch, Integer lastScore,
                         Set<String> lastFactors, Boolean lastBurstBand, Long ipChangeHoldUntilNanos) {

        /** 모든 필드가 빈 초기 스냅샷 — 첫 관측(주체 미기록)의 출발점. 불변이라 공유해도 안전. */
        static final State EMPTY = new State(null, null, 0L, null, null, null, null);

        /** 이번 IP(논리 축)와 hold 만료 시각을 반영한다(IP 변화 판정·hold 시작은 호출부가 계산해 넘긴다). */
        State withIp(String ip, Long holdUntilNanos) {
            return new State(ip, lastNetworkIp, epoch, lastScore, lastFactors, lastBurstBand, holdUntilNanos);
        }

        /** 이번 네트워크 축 IP를 반영한다(커널 L4 신호↔주체 번역의 매칭 기준). */
        State withNetworkIp(String networkIp) {
            return new State(lastSeenIp, networkIp, epoch, lastScore, lastFactors, lastBurstBand,
                    ipChangeHoldUntilNanos);
        }

        /** 이번 점수·팩터 구성을 반영한다. {@code bump=true}(위험 변화)면 epoch를 +1 한다(능동 무효화 토큰). */
        State withScore(int score, Set<String> factors, boolean bump) {
            return new State(lastSeenIp, lastNetworkIp, bump ? epoch + 1 : epoch, score, factors,
                    lastBurstBand, ipChangeHoldUntilNanos);
        }

        /** 이번 폭주 밴드를 반영한다(다음 평가의 히스테리시스 기준). */
        State withBand(boolean band) {
            return new State(lastSeenIp, lastNetworkIp, epoch, lastScore, lastFactors, band,
                    ipChangeHoldUntilNanos);
        }

        /** 위험 맥락을 비우되 epoch만 보존한다(데모 리셋 — {@link #evict}의 단조성 보존 근거 참고). */
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

    /**
     * 테스트용 — 단조 시계를 주입해 hold 만료를 결정적으로 검증한다({@link L4RateFlagStore}와 같은 패턴).
     * 평가 흐름 테스트(다른 패키지의 {@code AssessmentServiceTest})도 시계를 쥐어야 해서 public.
     */
    public SubjectRiskState(Duration ipChangeHold, LongSupplier nanoClock) {
        this.ipChangeHoldNanos = ipChangeHold.toNanos();
        this.nanoClock = nanoClock;
    }

    /** 직전 관측 IP(논리 축)를 반환한다(없으면 {@code null} = 첫 관측 → IP 변화로 치지 않음). */
    public String lastSeenIp(String subject) {
        State s = states.get(subject);
        return s == null ? null : s.lastSeenIp();
    }

    /**
     * 이번 관측의 네트워크 축 IP(게이트웨이 소켓 피어 = 커널이 패킷에서 보는 좌표)를 기록한다 —
     * L4 신호↔주체 번역({@link #subjectsByNetworkIp})의 매칭 기준. 논리 축({@link #recordIp})과 달리
     * 변화 판정·hold가 없다(네트워크 경로 변경은 위험 신호가 아니라 관측 좌표의 이동일 뿐이다).
     * null/blank는 무시(미상은 기준을 덮지 않음 — 논리 축과 같은 원칙).
     */
    public void recordNetworkIp(String subject, String networkIp) {
        if (networkIp == null || networkIp.isBlank()) {
            return;
        }
        states.compute(subject, (k, s) -> (s == null ? State.EMPTY : s).withNetworkIp(networkIp));
    }

    /**
     * 이번 관측 IP를 기록한다(다음 요청의 IP 변화 비교 기준). null/blank는 무시(미상 IP는 기준을 덮지 않음).
     * 직전 IP와 <b>다르면</b> 그 순간부터 hold를 시작(재변화는 연장)한다 — 비교 기준이 덮여도
     * "최근에 바뀌었다"는 사실은 {@link #ipChangeHeld}로 hold 동안 살아남는다. 첫 관측은 변화가 아니다.
     */
    public void recordIp(String subject, String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return;
        }
        states.compute(subject, (k, s) -> {
            State cur = s == null ? State.EMPTY : s;
            boolean changed = cur.lastSeenIp() != null && !sourceIp.equals(cur.lastSeenIp());
            // 양쪽 다 Long으로 박싱 — long/Long 혼합 삼항은 null 쪽을 언박싱해 NPE가 난다.
            Long holdUntil = changed
                    ? Long.valueOf(nanoClock.getAsLong() + ipChangeHoldNanos)   // 변화 관측: hold 시작/연장
                    : cur.ipChangeHoldUntilNanos();                             // 동일/첫 관측: 기존 hold 유지(시간 만료에 맡김)
            return cur.withIp(sourceIp, holdUntil);
        });
    }

    /**
     * 이 주체의 IP 변화 hold가 아직 유효한가(= 최근 hold 창 안에 IP가 바뀐 적 있는가).
     * (now - holdUntil) >= 0 이면 만료 — 차이로 비교해 nanoTime 래핑에도 안전하다. 만료 판정만 하고
     * 엔트리는 지우지 않는다(주체당 상태 한 건이라 크기 문제가 없고, 다음 변화가 값을 덮는다).
     */
    public boolean ipChangeHeld(String subject) {
        State s = states.get(subject);
        Long holdUntil = s == null ? null : s.ipChangeHoldUntilNanos();
        return holdUntil != null && nanoClock.getAsLong() - holdUntil < 0;
    }

    /** 주체의 현재 epoch(없으면 0). 캐시 키/검증용 조회. */
    public long currentEpoch(String subject) {
        State s = states.get(subject);
        return s == null ? 0L : s.epoch();
    }

    /**
     * 이번 위험 점수·기여 팩터 구성을 반영하고 현재 epoch를 반환한다. 점수 <b>또는 팩터 이름 집합</b>이
     * 직전과 달라졌을 때만 epoch를 +1 한다(능동 무효화). 팩터 집합을 함께 보는 이유: 가중치가 같은 팩터의
     * 교체(rate-burst 40 ↔ rate-l4 40 등)는 점수 동률이라 점수 비교만으론 위험의 성격 변화를 놓친다.
     * 첫 관측은 bump 없이 기록만 한다(epoch 0) — 변화가 아니라 기준 설정이므로.
     *
     * @param subject     대상 주체
     * @param score       이번에 산출된 위험 점수(0~100)
     * @param factorNames 점수에 기여한 팩터 이름 집합({@code null}=빈 집합으로 취급)
     * @return 반영 후 주체의 현재 epoch
     */
    public long recordScore(String subject, int score, Set<String> factorNames) {
        Set<String> factors = factorNames == null ? Set.of() : Set.copyOf(factorNames);
        State updated = states.compute(subject, (k, s) -> {
            State cur = s == null ? State.EMPTY : s;
            // 첫 관측(lastScore=null)·동일 점수+동일 구성은 기준 설정/유지라 bump 없음.
            boolean bump = cur.lastScore() != null
                    && (cur.lastScore() != score || !factors.equals(cur.lastFactors()));
            return cur.withScore(score, factors, bump);
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
        states.compute(subject, (k, s) -> (s == null ? State.EMPTY : s).withBand(band));
    }

    /**
     * 직전 관측의 <b>네트워크 축</b> IP가 {@code networkIp}인 주체들을 찾는다 — 커널(XDP) L4 신호는
     * <b>패킷 소스 IP</b> 단위로 도착하므로, 같은 좌표계(소켓 피어)로 기록된 축과 맞춰야 번역이 된다.
     * 논리 축({@code lastSeenIp}, XFF 기반)으로 맞추면 LB/프록시 뒤에서 두 좌표가 달라 번역이 항상
     * 실패한다(rate-l4 영영 미반영). 전수 순회지만 주체 수는 세션 수 규모라 데모/단일 PIP에선
     * 충분하다(역인덱스는 필요해질 때).
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

    /**
     * 데모 리셋: 주체의 위험 맥락(직전 IP 두 축·IP 변화 hold·직전 점수·직전 밴드)을 비운다 — 다음 관측은 첫 관측으로
     * 취급된다(변화 아님, bump 없음). 단 <b>epoch는 보존</b>한다: 게이트웨이의 epoch 학습이 단조(max)라 여기서
     * 되돌리면 게이트웨이 조회(옛 큰 epoch)와 적재(새 작은 epoch)가 영구히 갈려 그 주체가 캐시 불능이 된다.
     */
    public void evict(String subject) {
        states.computeIfPresent(subject, (k, s) -> s.resetKeepingEpoch());
    }
}
