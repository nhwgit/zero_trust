package com.ztg.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;

import reactor.core.publisher.Mono;

/**
 * PEP(Gateway) → PDP 질의 클라이언트(리액티브 WebClient).
 *
 * <p>게이트웨이는 WebFlux 기반이므로 블로킹 호출을 섞지 않도록 논블로킹 {@link WebClient}로
 * PDP를 호출한다. 오류(PDP 다운 등)는 여기서 삼키지 않고 그대로 흘려보낸다 —
 * fail-close(판단 불가 → 차단)는 호출부({@link JwtAuthGlobalFilter})가 책임진다.
 */
@Component
public class PdpClient {

    private final WebClient webClient;

    public PdpClient(WebClient.Builder builder,
                     @Value("${ztg.gateway.pdp-base-uri}") String pdpBaseUri) {
        this.webClient = builder.baseUrl(pdpBaseUri).build();
    }

    public Mono<DecisionResponse> decide(DecisionRequest request) {
        return webClient.post()
                .uri("/decision")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(DecisionResponse.class);
    }
}
