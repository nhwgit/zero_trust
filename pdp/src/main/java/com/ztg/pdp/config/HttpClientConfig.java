package com.ztg.pdp.config;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.StringUtils;

/**
 * PDP→PIP {@code RestClient}가 커넥션 풀(keep-alive)을 쓰도록 강제한다 — 기본 빌더는 요청마다 새 연결이라
 * 고부하에서 TIME_WAIT 포트 고갈로 PIP 조회가 실패해 fail-close(DENY)로 샌다.
 * {@code ztg.pdp.pip-ssl-bundle}이 설정되면 그 SSL 번들로 mTLS를 적용하고, 비어 있으면 평문이다.
 */
@Configuration
public class HttpClientConfig {

    @Bean
    RestClientCustomizer pipRestClientCustomizer(
            @Value("${ztg.pdp.pip-pool.max-total:200}") int maxTotal,
            @Value("${ztg.pdp.pip-pool.max-per-route:200}") int maxPerRoute,
            @Value("${ztg.pdp.pip-pool.connect-timeout-ms:2000}") long connectTimeoutMs,
            @Value("${ztg.pdp.pip-pool.socket-timeout-ms:5000}") long socketTimeoutMs,
            @Value("${ztg.pdp.pip-ssl-bundle:}") String pipSslBundle,
            SslBundles sslBundles) {

        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
                .setSocketTimeout(Timeout.ofMilliseconds(socketTimeoutMs))
                // 오래된 연결을 영구 재사용하지 않도록 TTL을 둔다(서버 재기동·NAT 만료 대비).
                .setTimeToLive(TimeValue.ofMinutes(5))
                .build();

        PoolingHttpClientConnectionManagerBuilder cmBuilder = PoolingHttpClientConnectionManagerBuilder.create()
                .setMaxConnTotal(maxTotal)
                .setMaxConnPerRoute(maxPerRoute)   // 기본 5는 동시 VU 대비 과소 → 직접 상향
                .setDefaultConnectionConfig(connectionConfig);

        if (StringUtils.hasText(pipSslBundle)) {
            SSLContext sslContext = sslBundles.getBundle(pipSslBundle).createSslContext();
            SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactoryBuilder.create()
                    .setSslContext(sslContext)
                    .build();
            cmBuilder.setSSLSocketFactory(socketFactory);
        }

        PoolingHttpClientConnectionManager connectionManager = cmBuilder.build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .evictIdleConnections(TimeValue.ofSeconds(30))
                .build();

        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return builder -> builder.requestFactory(factory);
    }
}
