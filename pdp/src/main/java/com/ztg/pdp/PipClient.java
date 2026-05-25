package com.ztg.pdp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.ztg.common.SubjectAttributes;

/**
 * PDP → PIP 호출 클라이언트. 판단에 필요한 주체 속성을 PIP에서 가져온다.
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

    public SubjectAttributes fetchAttributes(String subject) {
        return restClient.get()
                .uri("/pip/attributes/{subject}", subject)
                .retrieve()
                .body(SubjectAttributes.class);
    }
}
