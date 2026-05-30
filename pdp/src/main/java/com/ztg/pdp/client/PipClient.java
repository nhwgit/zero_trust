package com.ztg.pdp;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.ztg.common.AssessRequest;
import com.ztg.common.PipAssessment;
import com.ztg.common.RiskSignals;
import com.ztg.common.web.RequestId;

/**
 * PDP → PIP 호출 클라이언트. 판단에 필요한 맥락(저장 속성 + 동적 위험점수 + epoch)을 PIP에서 가져온다.
 *
 * <p>호출 실패(네트워크/PIP 다운)는 여기서 삼키지 않고 그대로 던진다.
 * fail-close 판단(맥락 조회 불가 → DENY)은 상위 {@link PolicyDecisionService}가 책임진다.
 */
@Component
public class PipClient {

    private final RestClient restClient;

    public PipClient(RestClient.Builder builder,
                     @Value("${ztg.pdp.pip-base-uri}") String pipBaseUri) {
        this.restClient = builder.baseUrl(pipBaseUri).build();
    }

    /**
     * 주체를 휘발성 신호 맥락에서 평가한다. PIP가 저장 속성 + 동적 위험점수 + 현재 epoch를 묶어 돌려준다.
     */
    public PipAssessment assess(String subject, RiskSignals signals) {
        // 인바운드 요청의 추적 ID(RequestIdFilter가 MDC에 채움)를 PIP로 이어 전파한다(분산 추적).
        String requestId = MDC.get(RequestId.MDC_KEY);
        return restClient.post()
                .uri("/pip/assess")
                .headers(h -> {
                    if (requestId != null) {
                        h.set(RequestId.HEADER, requestId);
                    }
                })
                .body(new AssessRequest(subject, signals))
                .retrieve()
                .body(PipAssessment.class);
    }
}
