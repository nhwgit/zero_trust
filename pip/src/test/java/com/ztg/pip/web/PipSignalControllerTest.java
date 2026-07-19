package com.ztg.pip.web;

import com.ztg.pip.fanout.EpochPublisher;
import com.ztg.pip.service.AssessmentService;
import com.ztg.pip.service.RiskEngine;
import com.ztg.pip.service.RiskProperties;
import com.ztg.pip.store.L4RateFlagStore;
import com.ztg.pip.store.SubjectAttributeStore;
import com.ztg.pip.store.SubjectRiskState;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import com.ztg.common.model.RiskSignals;

/**
 * 신호 수신 표면 검증 — 핵심은 ack에 실리는 <b>enforcement 지시</b>다:
 * PIP(판단)가 "이 IP를 hold와 같은 TTL 동안 에지에서 차단하라"를 반환하고, 에이전트가 이를
 * 커널 deny map에 번역한다. TTL == hold 동기화(세션 무효화와 에지 차단의 가역성 창 일치)를 검증한다.
 */
class PipSignalControllerTest {

    private final EpochPublisher silent = (subject, epoch) -> {};
    private final RiskEngine riskEngine = new RiskEngine(new RiskProperties(40, 30, 40, 40, 15, 60, 40, 9, 18));
    private final SubjectRiskState state = new SubjectRiskState(Duration.ofSeconds(30));
    private final L4RateFlagStore l4Flags = new L4RateFlagStore(Duration.ofSeconds(30));
    // 공개 생성자(실제 시계) 사용 — 이 테스트는 점수 산수가 아니라 ack 계약(enforcement)만 단언하므로 무해.
    private final AssessmentService service =
            new AssessmentService(new SubjectAttributeStore(), riskEngine, state, silent, l4Flags);
    private final PipSignalController controller = new PipSignalController(service, l4Flags);

    @Test
    void ack_carries_deny_enforcement_with_ttl_synced_to_hold() {
        // alice가 IP A에서 관측된 상태 → 신호가 주체 번역까지 되는 정상 경로.
        service.assess("alice", RiskSignals.direct("1.1.1.1", 0, 12));

        var ack = controller.rateL4(new PipSignalController.RateL4Signal("1.1.1.1", 87, 430, 5));

        assertThat(ack.sourceIp()).isEqualTo("1.1.1.1");
        assertThat(ack.reassessedSubjects()).containsExactly("alice");
        // 판단→제어의 계약: action=deny, TTL은 hold(30s)와 동일 — 두 축(세션/에지)이 같은 시점에 풀린다.
        assertThat(ack.enforcement().action()).isEqualTo("deny");
        assertThat(ack.enforcement().ttlSeconds()).isEqualTo(30L);
    }

    @Test
    void unseen_ip_still_gets_enforcement_directive() {
        // 주체 번역이 안 돼도(빈 목록) 에지 차단 지시는 나간다 — IP 축 차단은 주체 축과 독립.
        var ack = controller.rateL4(new PipSignalController.RateL4Signal("6.6.6.6", 99, 500, 5));
        assertThat(ack.reassessedSubjects()).isEmpty();
        assertThat(ack.enforcement().action()).isEqualTo("deny");
    }

    @Test
    void blank_source_ip_is_rejected() {
        assertThatThrownBy(() -> controller.rateL4(new PipSignalController.RateL4Signal(" ", 1, 1, 5)))
                .isInstanceOf(ResponseStatusException.class);
    }
}
