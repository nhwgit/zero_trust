package com.ztg.pip.web;

import java.util.List;

import com.ztg.pip.service.AssessmentService;
import com.ztg.pip.store.L4RateFlagStore;
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
 * 에지 차단(IP 축)의 가역성 창을 하나로 유지한다.
 */
@RestController
public class PipSignalController {

    record RateL4Signal(String sourceIp, long synsInWindow, long packetsInWindow, int windowSeconds) {}

    /** 에지 차단 지시 — 에이전트가 커널 deny map에 번역한다. action은 현재 "deny" 하나. */
    record Enforcement(String action, long ttlSeconds) {}

    record RateL4Ack(String sourceIp, List<String> reassessedSubjects, Enforcement enforcement) {}

    private final AssessmentService assessmentService;
    private final L4RateFlagStore l4Flags;

    public PipSignalController(AssessmentService assessmentService, L4RateFlagStore l4Flags) {
        this.assessmentService = assessmentService;
        this.l4Flags = l4Flags;
    }

    @PostMapping("/pip/signals/rate-l4")
    public RateL4Ack rateL4(@RequestBody RateL4Signal signal) {
        if (signal.sourceIp() == null || signal.sourceIp().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceIp is required");
        }
        List<String> affected = assessmentService.applyL4RateSignal(
                signal.sourceIp(), signal.synsInWindow(), signal.windowSeconds());
        return new RateL4Ack(signal.sourceIp(), affected,
                new Enforcement("deny", l4Flags.holdSeconds()));
    }
}
