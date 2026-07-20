package com.ztg.pip.web;

import java.util.List;

import com.ztg.common.net.CidrRanges;
import com.ztg.pip.config.EdgeBlockExemptProperties;
import com.ztg.pip.service.AssessmentService;
import com.ztg.pip.store.L4RateFlagStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * 커널(XDP) 에이전트가 밀어 넣는 out-of-band 위험 신호({@code rate.l4})의 수신 표면.
 * 임계 판정은 에이전트 몫이고, PIP는 받은 IP를 hold 동안 플래그하고 해당 주체를 재평가한다.
 *
 * <p>ack에 에지 차단 지시(enforcement)를 실어 보낸다 — TTL을 hold와 동기화해 세션 무효화(주체 축)와
 * 에지 차단(IP 축)의 가역성 창을 하나로 유지한다. 단 신호 IP가 에지 차단 제외 대역(신뢰 프록시/LB)에
 * 들면 지시를 생략한다 — 공유 IP를 드랍하면 경유 사용자 전원이 끊기므로, 세션 축 재평가만 남긴다.
 */
@RestController
public class PipSignalController {

    private static final Logger log = LoggerFactory.getLogger(PipSignalController.class);

    record RateL4Signal(String sourceIp, long synsInWindow, long packetsInWindow, int windowSeconds) {}

    /** 에지 차단 지시 — 에이전트가 커널 deny map에 번역한다. action은 현재 "deny" 하나. */
    record Enforcement(String action, long ttlSeconds) {}

    /** enforcement가 {@code null}이면 차단 지시 없음 — 에이전트는 그 경우 관측 전용으로 동작한다. */
    record RateL4Ack(String sourceIp, List<String> reassessedSubjects, Enforcement enforcement) {}

    private final AssessmentService assessmentService;
    private final L4RateFlagStore l4Flags;
    private final CidrRanges edgeBlockExempt;

    public PipSignalController(AssessmentService assessmentService, L4RateFlagStore l4Flags,
            EdgeBlockExemptProperties exemptProperties) {
        this.assessmentService = assessmentService;
        this.l4Flags = l4Flags;
        this.edgeBlockExempt = CidrRanges.parse(exemptProperties.edgeBlockExempt(), "ztg.pip.edge-block-exempt");
    }

    @PostMapping("/pip/signals/rate-l4")
    public RateL4Ack rateL4(@RequestBody RateL4Signal signal) {
        if (signal.sourceIp() == null || signal.sourceIp().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceIp is required");
        }
        List<String> affected = assessmentService.applyL4RateSignal(
                signal.sourceIp(), signal.synsInWindow(), signal.windowSeconds());
        if (edgeBlockExempt.containsLiteral(signal.sourceIp())) {
            log.info("l4-rate signal ip={} in edge-block-exempt range -> enforcement suppressed (session reassess only)",
                    signal.sourceIp());
            return new RateL4Ack(signal.sourceIp(), affected, null);
        }
        return new RateL4Ack(signal.sourceIp(), affected,
                new Enforcement("deny", l4Flags.holdSeconds()));
    }
}
