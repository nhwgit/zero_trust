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

    /** RiskEngine은 @Value 기본값을 코드로 재현(미신뢰40/IP변화30/폭주40/L4폭주40/업무외15, 폭주임계60, 업무 9-18). */
    private final RiskEngine riskEngine = new RiskEngine(40, 30, 40, 40, 15, 60, 9, 18);
    private final SubjectRiskState state = new SubjectRiskState();
    private final L4RateFlagStore l4Flags = new L4RateFlagStore(Duration.ofSeconds(30));
    /** 12시(업무시간 내)로 고정 — out-of-band 재평가의 off-hours 가중을 배제해 산수를 예측 가능하게. */
    private final Clock noon = Clock.fixed(Instant.parse("2026-07-11T12:00:00Z"), ZoneOffset.UTC);
    private final AssessmentService service =
            new AssessmentService(new SubjectAttributeStore(), riskEngine, state, capturing, l4Flags, noon);

    @Test
    void normal_then_new_ip_and_burst_raises_score_and_bumps_epoch() {
        // 1) 정상: alice(baseline 10, finance, 신뢰), 기존 IP, 폭주 없음, 업무시간 → score 10, epoch 0.
        PipAssessment first = service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));
        assertThat(first.attributes().subject()).isEqualTo("alice");
        assertThat(first.risk().score()).isEqualTo(10);
        assertThat(first.epoch()).isZero();

        // 2) 같은 세션에서 새 IP(+30) + 폭주 70>60(+40) → score 80(임계), 점수 변화 → epoch 1.
        PipAssessment second = service.assess("alice", new RiskSignals("9.9.9.9", 70, 12));
        assertThat(second.risk().score()).isEqualTo(80);
        assertThat(second.epoch()).isEqualTo(1L);
        // 설명 가능: 거부 사유에 실릴 기여 신호 내역이 두 신호를 모두 담는다.
        assertThat(second.risk().explain()).contains("ip-change").contains("rate-burst");

        // fan-out은 epoch가 오른 그 한 번만 일어난다(첫 관측은 기준 설정이라 전파 없음).
        assertThat(published).containsExactly(new Published("alice", 1L));
    }

    @Test
    void stable_risk_does_not_bump_epoch() {
        service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));   // epoch 0
        PipAssessment again = service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));
        assertThat(again.risk().score()).isEqualTo(10);
        assertThat(again.epoch()).isZero();   // 점수 동일 → 캐시 유지(불필요한 무효화 없음)
        // 점수 불변이면 fan-out도 침묵한다(채널 잡음 없음 = 불필요한 무효화 없음).
        assertThat(published).isEmpty();
    }

    @Test
    void l4_rate_signal_reassesses_subjects_on_that_ip_and_bumps_epoch() {
        // D3 Step 2 코어: 커널(XDP) 신호가 기존 능동 무효화 경로(점수 변화 → epoch bump → fan-out)를 탄다.
        // 1) alice가 IP A에서 정상 관측(score 10, epoch 0) — lastSeenIp=A가 신호→주체 번역의 근거가 된다.
        service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));

        // 2) 에이전트가 IP A의 L4 레이트 초과를 보고 → alice가 재평가되고(+rate-l4 40) epoch가 오른다.
        List<String> affected = service.applyL4RateSignal("1.1.1.1", 87, 5);
        assertThat(affected).containsExactly("alice");
        assertThat(state.currentEpoch("alice")).isEqualTo(1L);
        assertThat(published).containsExactly(new Published("alice", 1L));   // fan-out도 같은 순간 발화

        // 3) 이후 실제 요청 평가에도 플래그가 살아 있는 동안 rate-l4가 가중된다(hold = 위험적응 유지 기간).
        PipAssessment next = service.assess("alice", new RiskSignals("1.1.1.1", 0, 12));
        assertThat(next.risk().score()).isEqualTo(50);   // baseline 10 + rate-l4 40
        assertThat(next.risk().explain()).contains("rate-l4");
    }

    @Test
    void l4_rate_signal_for_unseen_ip_touches_no_subject_but_holds_flag() {
        // 신호 IP를 쓰는 주체가 없으면 재평가 대상 없음 — 다만 플래그는 남아, 그 IP로 처음 오는
        // 평가부터 가중된다(신호가 로그인보다 먼저 도착하는 경합에도 안전).
        assertThat(service.applyL4RateSignal("6.6.6.6", 99, 5)).isEmpty();
        assertThat(published).isEmpty();

        PipAssessment first = service.assess("alice", new RiskSignals("6.6.6.6", 0, 12));
        assertThat(first.risk().explain()).contains("rate-l4");
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
