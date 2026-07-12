package com.ztg.pip.web;

import java.util.List;

import com.ztg.pip.service.AssessmentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * 요청 밖(out-of-band) 위험 신호의 수신 표면(D3 Step 2). 평가 질의({@code /pip/assess}, PDP가 호출)와
 * 달리, 커널(XDP) 에이전트가 <b>능동적으로 밀어 넣는</b> 신호를 받는다 — 신호 타입 {@code rate.l4}.
 *
 * <p>임계 판정은 에이전트 몫이다: 에이전트가 커널 map을 폴링해 윈도우 레이트를 계산하고, 임계를 넘었을
 * 때만 POST한다(PIP는 mTLS로 잠긴 데이터 포트라 발신자를 신뢰 — 관측치는 근거로만 싣는다).
 * PIP는 받은 IP를 hold 동안 플래그하고 해당 주체를 재평가한다(→ epoch bump → 능동 무효화).
 */
@RestController
public class PipSignalController {

    /** 에이전트 보고 본문 — 관측 창의 SYN 수(임계 초과 근거)와 창 길이. 패킷 수는 참고용. */
    record RateL4Signal(String sourceIp, long synsInWindow, long packetsInWindow, int windowSeconds) {}

    /** 수신 확인 — 재평가가 걸린 주체 목록(데모 가시성: 신호→주체 번역 결과를 바로 보여준다). */
    record RateL4Ack(String sourceIp, List<String> reassessedSubjects) {}

    private final AssessmentService assessmentService;

    public PipSignalController(AssessmentService assessmentService) {
        this.assessmentService = assessmentService;
    }

    @PostMapping("/pip/signals/rate-l4")
    public RateL4Ack rateL4(@RequestBody RateL4Signal signal) {
        if (signal.sourceIp() == null || signal.sourceIp().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceIp is required");
        }
        List<String> affected = assessmentService.applyL4RateSignal(
                signal.sourceIp(), signal.synsInWindow(), signal.windowSeconds());
        return new RateL4Ack(signal.sourceIp(), affected);
    }
}
