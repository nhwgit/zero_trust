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
 * PDP→PIP 호출에 쓰는 {@link org.springframework.web.client.RestClient}가 <b>커넥션 풀(keep-alive)</b>을
 * 쓰도록 강제한다.
 *
 * <p><b>왜:</b> 기본 {@code RestClient.Builder}는 요청마다 새 TCP 연결을 열고 닫는다. 고부하(수천 rps)에서
 * 닫힌 소켓이 TIME_WAIT로 쌓여 클라이언트 측 <b>임시 포트가 고갈</b>되면 PIP 조회가
 * {@code Address already in use: connect}로 실패하고, PDP는 맥락을 못 모아 <b>fail-close(DENY)</b>로 샌다.
 * Apache HttpClient5의 풀드 커넥션 매니저로 연결을 재사용하면 포트 고갈 없이 안정적으로 처리한다.
 *
 * <p>풀 크기/타임아웃은 {@code ztg.pdp.pip-pool.*}로 노출한다(부하 측정 시 조정 가능).
 *
 * <p><b>mTLS:</b> {@code ztg.pdp.pip-ssl-bundle}이 설정되면(= mtls 프로파일) 그 SSL 번들의 SSLContext를
 * 풀의 소켓 팩토리에 주입한다 — PIP(https) 호출 시 자기 인증서를 제시하고 PIP를 CA로 검증한다(상호 TLS).
 * 비어 있으면(기본/테스트) 평문 그대로다.
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
            // 번들의 키스토어(클라 인증서)+트러스트스토어(CA)로 TLS 컨텍스트를 만들어 풀에 적용 → mTLS.
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
