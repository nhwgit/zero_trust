package com.ztg.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.ztg.common.DecisionRequest;
import com.ztg.common.DecisionResponse;
import com.ztg.common.web.RequestId;

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
    private final DecisionCache decisionCache;

    public PdpClient(WebClient.Builder builder,
                     @Value("${ztg.gateway.pdp-base-uri}") String pdpBaseUri,
                     DecisionCache decisionCache) {
        this.webClient = builder.baseUrl(pdpBaseUri).build();
        this.decisionCache = decisionCache;
    }

    /**
     * PDP에 인가를 질의한다. {@code requestId}를 헤더로 실어 PDP/PIP 로그까지 상관되게 한다(분산 추적).
     *
     * <p>같은 {@link DecisionRequest}에 대한 직전 결정이 캐시에 살아 있으면 PDP 왕복을 건너뛰고 즉시
     * 반환한다(핫 키 재요청의 p99/throughput 개선). 캐시에는 PDP가 실제로 내린 결정만 적재한다 —
     * 호출 실패로 인한 fail-close는 이 메서드 밖(호출부)에서 일어나므로 캐시되지 않는다(오류를 굳히지 않음).
     */
    public Mono<DecisionResponse> decide(DecisionRequest request, String requestId) {
        DecisionResponse cached = decisionCache.getIfPresent(request);
        if (cached != null) {
            return Mono.just(cached);
        }
        return webClient.post()
                .uri("/decision")
                .header(RequestId.HEADER, requestId)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(DecisionResponse.class)
                .doOnNext(decision -> decisionCache.put(request, decision));
    }
}
