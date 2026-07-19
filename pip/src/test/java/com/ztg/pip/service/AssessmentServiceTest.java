package com.ztg.pip.service;

import com.ztg.pip.fanout.EpochPublisher;
import com.ztg.pip.store.L4RateFlagStore;
import com.ztg.pip.store.SubjectAttributeStore;
import com.ztg.pip.store.SubjectRiskState;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ztg.common.model.PipAssessment;
import com.ztg.common.model.RiskSignals;

/**
 * PIP 평가 오케스트레이션 L2 — 점수 산출 + epoch 발급 + fan-out 전파를 한 흐름으로 검증한다.
 * 핵심 시나리오: 같은 주체가 정상(저위험)에서 새 IP+폭주로 바뀌면 점수가 임계 위로 오르고
 * <b>epoch가 bump</b>된다 → 이것이 게이트웨이의 능동 캐시 무효화(재로그인 없는 ALLOW→DENY)를 떠받친다.
 * epoch가 오른 그 순간에만 fan-out publish가 일어나는지(다중 GW 즉시 전파)도 함께 본다.
 */
class AssessmentServiceTest {

    /** 발신점 호출을 포착하는 가짜 publisher — fan-out이 epoch 상승 때만(중복 없이) 일어나는지 검증한다. */
    private record Published(String subject, long epoch) {}
    private final List<Published> published = new ArrayList<>();
    private final EpochPublisher capturing = (subject, epoch) -> published.add(new Published(subject, epoch));

    /** RiskEngine은 @Value 기본값을 코드로 재현(미신뢰40/IP변화30/폭주40/L4폭주40/업무외15, 폭주 진입>60/해제≤40, 업무 9-18). */
    private final RiskEngine riskEngine = new RiskEngine(new RiskProperties(40, 30, 40, 40, 15, 60, 40, 9, 18));
    /** 가짜 단조 시계 — ip-change hold(30s)의 유지/만료를 결정적으로 검증한다. */
    private long nowNanos = 0;
    private final SubjectRiskState state = new SubjectRiskState(Duration.ofSeconds(30), () -> nowNanos);
    private final L4RateFlagStore l4Flags = new L4RateFlagStore(Duration.ofSeconds(30));
    /** 12시(업무시간 내)로 고정 — out-of-band 재평가의 off-hours 가중을 배제해 산수를 예측 가능하게. */
    private final Clock noon = Clock.fixed(Instant.parse("2026-07-11T12:00:00Z"), ZoneOffset.UTC);
    private final AssessmentService service =
            new AssessmentService(new SubjectAttributeStore(), riskEngine, state, capturing, l4Flags, noon);

    @Test
    void normal_then_new_ip_and_burst_raises_score_and_bumps_epoch() {
        // 1) 정상: alice(baseline 10, finance, 신뢰), 기존 IP, 폭주 없음, 업무시간 → score 10, epoch 0.
        PipAssessment first = service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));
        assertThat(first.attributes().subject()).isEqualTo("alice");
        assertThat(first.risk().score()).isEqualTo(10);
        assertThat(first.epoch()).isZero();

        // 2) 같은 세션에서 새 IP(+30) + 폭주 70>60(+40) → score 80(임계), 점수 변화 → epoch 1.
        PipAssessment second = service.assess("alice", RiskSignals.direct("9.9.9.9", 70, 12));
        assertThat(second.risk().score()).isEqualTo(80);
        assertThat(second.epoch()).isEqualTo(1L);
        // 설명 가능: 거부 사유에 실릴 기여 신호 내역이 두 신호를 모두 담는다.
        assertThat(second.risk().explain()).contains("ip-change").contains("rate-burst");

        // fan-out은 epoch가 오른 그 한 번만 일어난다(첫 관측은 기준 설정이라 전파 없음).
        assertThat(published).containsExactly(new Published("alice", 1L));
    }

    @Test
    void stable_risk_does_not_bump_epoch() {
        service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));   // epoch 0
        PipAssessment again = service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));
        assertThat(again.risk().score()).isEqualTo(10);
        assertThat(again.epoch()).isZero();   // 점수 동일 → 캐시 유지(불필요한 무효화 없음)
        // 점수 불변이면 fan-out도 침묵한다(채널 잡음 없음 = 불필요한 무효화 없음).
        assertThat(published).isEmpty();
    }

    @Test
    void l4_rate_signal_reassesses_subjects_on_that_ip_and_bumps_epoch() {
        // 핵심: 커널(XDP) 신호가 기존 능동 무효화 경로(점수 변화 → epoch bump → fan-out)를 탄다.
        // 1) alice가 IP A에서 정상 관측(score 10, epoch 0) — lastSeenIp=A가 신호→주체 번역의 근거가 된다.
        service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));

        // 2) 에이전트가 IP A의 L4 레이트 초과를 보고 → alice가 재평가되고(+rate-l4 40) epoch가 오른다.
        List<String> affected = service.applyL4RateSignal("1.1.1.1", 87, 5);
        assertThat(affected).containsExactly("alice");
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(published).containsExactly(new Published("alice", 1L));   // fan-out도 같은 순간 발화

        // 3) 이후 실제 요청 평가에도 플래그가 살아 있는 동안 rate-l4가 가중된다(hold = 위험적응 유지 기간).
        PipAssessment next = service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));
        assertThat(next.risk().score()).isEqualTo(50);   // baseline 10 + rate-l4 40
        assertThat(next.risk().explain()).contains("rate-l4");
    }

    @Test
    void l4_signal_during_burst_preserves_band_and_bumps_epoch_on_factor_swap() {
        // H1 시나리오: 실제 폭주 중인 주체에 L4 신호가 겹칠 때 — 재평가의 requestsInWindow=0은
        // "L7 레이트 미상"이지 실측이 아니므로 밴드 기준을 오염시키면 안 되고, rate-burst(+40)→rate-l4(+40)
        // 등점 팩터 교체도 위험 성격 변화라 epoch bump(→fan-out)가 나야 한다.
        // 1) alice가 폭주 중(70>60): score 50(baseline 10 + rate-burst 40), 밴드 true, epoch 0(첫 관측).
        PipAssessment burst = service.assess("alice", RiskSignals.direct("1.1.1.1", 70, 12));
        assertThat(burst.risk().score()).isEqualTo(50);
        assertThat(state.lastBurstBand("alice")).isTrue();

        // 2) 같은 IP에 L4 신호 → 재평가에서 rate-burst가 빠지고 rate-l4가 들어와 점수 동률(50)의
        //    팩터 교체. 종전 "점수 변화" 규칙이면 bump 누락(무효화 미발생) — 구성 변화 규칙으로 bump.
        service.applyL4RateSignal("1.1.1.1", 87, 5);
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(published).containsExactly(new Published("alice", 1L));   // fan-out도 발화
        // 가짜 0이 히스테리시스 기준을 덮지 않는다(밴드 보존 — 실요청 관측과의 발산 방지).
        assertThat(state.lastBurstBand("alice")).isTrue();

        // 3) 다음 실요청이 사이 구간(50)이어도 보존된 밴드로 rate-burst가 유지된다:
        //    10 + rate-burst 40 + rate-l4 40(플래그 생존) = 90. 밴드가 false로 오염됐다면
        //    50 ≤ 진입 임계 60이라 rate-burst가 빠져 50이 됐을 것(발산의 증상).
        PipAssessment next = service.assess("alice", RiskSignals.direct("1.1.1.1", 50, 12));
        assertThat(next.risk().score()).isEqualTo(90);
        assertThat(next.risk().explain()).contains("rate-burst").contains("rate-l4");
        assertThat(next.epoch()).isEqualTo(2L);   // 점수·구성 변화 → 정상 bump
    }

    @Test
    void l4_signal_behind_lb_translates_via_network_axis_without_corrupting_logical_ip() {
        // H3 시나리오: LB/프록시 뒤에선 논리 IP(XFF 첫 홉)와 네트워크 IP(소켓 피어=LB)가 다르다.
        // 커널(XDP)은 패킷 소스(네트워크 축)만 보므로, 번역·플래그 매칭이 논리 축이면 rate-l4가 영영 미반영.
        service.assess("alice", new RiskSignals("203.0.113.7", "10.0.0.9", 0, 12));   // score 10, epoch 0

        // 1) 신호 IP(네트워크 축)로 주체가 번역되고, rate-l4(+40)로 epoch가 오른다(능동 무효화).
        List<String> affected = service.applyL4RateSignal("10.0.0.9", 87, 5);
        assertThat(affected).containsExactly("alice");
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(published).containsExactly(new Published("alice", 1L));

        // 2) 재평가가 논리 기준(lastSeenIp)을 패킷 IP로 오염시키지 않는다 — 다음 실요청(같은 논리 IP)에서
        //    ip-change 오탐 없이 rate-l4만 가중된다: baseline 10 + rate-l4 40 = 50.
        assertThat(state.lastSeenIp("alice")).isEqualTo("203.0.113.7");
        PipAssessment next = service.assess("alice", new RiskSignals("203.0.113.7", "10.0.0.9", 0, 12));
        assertThat(next.risk().score()).isEqualTo(50);
        assertThat(next.risk().explain()).contains("rate-l4").doesNotContain("ip-change");
    }

    @Test
    void l4_rate_signal_for_unseen_ip_touches_no_subject_but_holds_flag() {
        // 신호 IP를 쓰는 주체가 없으면 재평가 대상 없음 — 다만 플래그는 남아, 그 IP로 처음 오는
        // 평가부터 가중된다(신호가 로그인보다 먼저 도착하는 경합에도 안전).
        assertThat(service.applyL4RateSignal("6.6.6.6", 99, 5)).isEmpty();
        assertThat(published).isEmpty();

        PipAssessment first = service.assess("alice", RiskSignals.direct("6.6.6.6", 0, 12));
        assertThat(first.risk().explain()).contains("rate-l4");
    }

    @Test
    void rate_oscillation_inside_hysteresis_band_does_not_bump_epoch() {
        // 경계 진동 시나리오: 진입(70>60) 후 레이트가 사이 구간(50)으로 진동해도 밴드가 유지돼
        // 점수가 안 변하고 → epoch bump도 fan-out도 없다. 해제 임계(≤40)까지 내려와야 한 번만 변한다.
        // 단일 임계였다면 50↔70 진동마다 점수가 ±40 출렁여 매번 epoch bump → 전 노드 캐시 무효화 폭풍.
        PipAssessment enter = service.assess("alice", RiskSignals.direct("1.1.1.1", 70, 12));
        assertThat(enter.risk().score()).isEqualTo(50);   // baseline 10 + rate-burst 40 (첫 관측: bump 없음)
        assertThat(enter.epoch()).isZero();

        PipAssessment held = service.assess("alice", RiskSignals.direct("1.1.1.1", 50, 12));
        assertThat(held.risk().score()).isEqualTo(50);    // 사이 구간: 밴드 유지 → 점수 불변
        assertThat(held.epoch()).isZero();                // epoch 안정
        assertThat(published).isEmpty();                  // fan-out 침묵(무효화 폭풍 없음)

        PipAssessment exited = service.assess("alice", RiskSignals.direct("1.1.1.1", 30, 12));
        assertThat(exited.risk().score()).isEqualTo(10);  // 해제 임계 이하: 그때 한 번 변화
        assertThat(exited.epoch()).isEqualTo(1L);
        assertThat(published).containsExactly(new Published("alice", 1L));
    }

    @Test
    void ip_change_weight_holds_across_reassessments_then_decays_once() {
        // 순간 신호의 약점 차단: IP 변화 직후의 재평가(비교 기준은 이미 새 IP)가 가중을 되돌리면
        // 탈취 DENY가 고위험 TTL(~1s)짜리 스파이크가 되어 재시도로 우회된다. hold 창(30s) 동안
        // 같은 신호명·가중치가 유지돼 점수가 안정(epoch 잡음 없음)되고, 창이 끝날 때 한 번만 하강한다.
        PipAssessment first = service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));
        assertThat(first.risk().score()).isEqualTo(10);              // 기준 IP 고정

        PipAssessment changed = service.assess("alice", RiskSignals.direct("9.9.9.9", 0, 12));
        assertThat(changed.risk().score()).isEqualTo(40);            // +ip-change 30
        assertThat(changed.epoch()).isEqualTo(1L);

        nowNanos += Duration.ofSeconds(10).toNanos();
        PipAssessment retried = service.assess("alice", RiskSignals.direct("9.9.9.9", 0, 12));
        assertThat(retried.risk().score()).isEqualTo(40);            // 재시도에도 점수 유지(hold)
        assertThat(retried.epoch()).isEqualTo(1L);                   // 점수 불변 → epoch 안정
        assertThat(retried.risk().explain()).contains("within hold window");

        nowNanos += Duration.ofSeconds(21).toNanos();                // 총 31s > hold 30s
        PipAssessment recovered = service.assess("alice", RiskSignals.direct("9.9.9.9", 0, 12));
        assertThat(recovered.risk().score()).isEqualTo(10);          // 창 경과: 자동 해제(가역성)
        assertThat(recovered.epoch()).isEqualTo(2L);                 // 하강도 변화 → 한 번의 bump로 수렴

        assertThat(published).containsExactly(new Published("alice", 1L), new Published("alice", 2L));
    }

    @Test
    void unknown_subject_is_max_risk() {
        // 미등록 주체는 보수적 기본 프로필(baseline 100, 미신뢰) → 점수 100으로 clamp.
        PipAssessment res = service.assess("mallory", RiskSignals.none());
        assertThat(res.risk().score()).isEqualTo(100);
    }

    @Test
    void null_signals_fall_back_to_neutral() {
        // 신호 누락(게이트웨이 미주입 등)은 위험 가중이 아니라 무가중 — baseline만 반영.
        PipAssessment res = service.assess("alice", null);
        assertThat(res.risk().score()).isEqualTo(10);
    }
}
