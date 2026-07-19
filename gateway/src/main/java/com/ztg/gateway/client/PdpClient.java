package com.ztg.gateway.client;

import com.ztg.gateway.cache.DecisionCache;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientSsl;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import com.ztg.common.model.DecisionRequest;
import com.ztg.common.model.DecisionResponse;
import com.ztg.common.web.RequestId;

import reactor.core.publisher.Mono;

/**
 * PEP(Gateway) → PDP 질의 클라이언트(논블로킹 {@link WebClient}).
 *
 * <p>오류(PDP 다운 등)는 삼키지 않고 그대로 흘려보낸다 — fail-close(판단 불가 → 차단)는
 * 호출부가 책임진다. {@code ztg.gateway.pdp-ssl-bundle}이 설정되면 해당 SSL 번들로 mTLS를 구성한다.
 */
@Component
public class PdpClient {

    private final WebClient webClient;
    private final DecisionCache decisionCache;

    public PdpClient(WebClient.Builder builder,
                     @Value("${ztg.gateway.pdp-base-uri}") String pdpBaseUri,
                     @Value("${ztg.gateway.pdp-ssl-bundle:}") String pdpSslBundle,
                     ObjectProvider<WebClientSsl> sslProvider,
                     DecisionCache decisionCache) {
        builder.baseUrl(pdpBaseUri);
        if (StringUtils.hasText(pdpSslBundle)) {
            WebClientSsl ssl = sslProvider.getIfAvailable();
            if (ssl == null) {
                throw new IllegalStateException(
                        "pdp-ssl-bundle '" + pdpSslBundle + "'이 설정됐으나 WebClientSsl을 쓸 수 없다");
            }
            builder.apply(ssl.fromBundle(pdpSslBundle));
        }
        this.webClient = builder.build();
        this.decisionCache = decisionCache;
    }

    /**
     * PDP에 인가를 질의한다. {@code requestId} 헤더로 PDP/PIP 로그까지 상관시킨다.
     * 캐시에는 PDP가 실제로 내린 결정만 적재한다 — 호출 실패의 fail-close는 캐시되지 않는다.
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
