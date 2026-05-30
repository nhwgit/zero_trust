package com.ztg.gateway;

import com.ztg.gateway.filter.JwtAuthGlobalFilter;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * e2e 통합 테스트 — <b>실제 Keycloak 컨테이너</b>에서 토큰을 발급받아 게이트웨이를 태운다.
 *
 * <p>단위 테스트({@link JwtAuthGlobalFilterTest})는 {@code ReactiveJwtDecoder}를 mock으로 대체하므로
 * "진짜 서명/iss/exp 검증"은 검증하지 못한다. 이 테스트는 그 빈틈을 메운다:
 * Keycloak이 발급한 진짜 RS256 토큰을 게이트웨이가 JWKS로 검증하고, 인가(PDP) 결과에 따라
 * allow→백엔드 전달 / deny·장애→차단(fail-close)으로 갈리는 전체 경로를 확인한다.
 *
 * <p>경계: PDP와 resource-api(백엔드)는 {@link MockWebServer} stub으로 대체한다 —
 * 정책 로직은 이미 단위 테스트가 커버하므로, 여기서는 게이트웨이의 <b>실제 토큰 검증 경로</b>만
 * 끝까지 태우고 PDP 응답(ALLOW/DENY/장애)은 stub으로 구동한다.
 *
 * <p>Docker가 필요하므로 {@code @Tag("integration")}으로 묶어 기본 {@code test}/{@code build}에서는
 * 제외하고, {@code ./gradlew :gateway:integrationTest}로만 실행한다(build.gradle 참조).
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayKeycloakE2eTest {

    private static final String REALM = "ztg";
    private static final String CLIENT_ID = "ztg-api";
    private static final String CLIENT_SECRET = "ztg-api-secret";
    private static final String TRUST_SECRET = "e2e-trust-secret";

    /** 실제 IdP. realm은 테스트 리소스의 ztg-realm.json을 기동 시 import 한다. */
    @Container
    static final GenericContainer<?> keycloak =
            new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.0"))
                    .withExposedPorts(8080)
                    .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                    .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                    .withEnv("KC_HTTP_ENABLED", "true")
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("ztg-realm.json"),
                            "/opt/keycloak/data/import/ztg-realm.json")
                    .withCommand("start-dev", "--import-realm")
                    // realm OIDC discovery가 200이면 = HTTP 기동 + realm import 완료 신호.
                    .waitingFor(Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                            .forPort(8080)
                            .withStartupTimeout(Duration.ofMinutes(3)));

    /** PDP stub — 게이트웨이가 /decision으로 인가를 질의한다. 응답을 테스트마다 enqueue로 구동. */
    static MockWebServer pdpStub;
    /** 백엔드(resource-api) stub — ALLOW일 때만 게이트웨이가 여기로 전달한다. */
    static MockWebServer backendStub;

    static {
        pdpStub = new MockWebServer();
        backendStub = new MockWebServer();
        try {
            pdpStub.start();
            backendStub.start();
        } catch (IOException e) {
            throw new IllegalStateException("stub 서버 기동 실패", e);
        }
    }

    @DynamicPropertySource
    static void wireGateway(DynamicPropertyRegistry registry) {
        String issuer = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080)
                + "/realms/" + REALM;
        // 게이트웨이 application.yml의 환경변수 플레이스홀더 이름으로 직접 주입한다.
        registry.add("KC_ISSUER_URI", () -> issuer);
        registry.add("PDP_BASE_URI", () -> "http://localhost:" + pdpStub.getPort());
        registry.add("RESOURCE_API_URI", () -> "http://localhost:" + backendStub.getPort());
        registry.add("GATEWAY_TRUST_SECRET", () -> TRUST_SECRET);
    }

    @AfterAll
    static void stopStubs() throws IOException {
        pdpStub.shutdown();
        backendStub.shutdown();
    }

    @Autowired
    WebTestClient client;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void no_token_is_rejected_401_before_pdp() {
        // stub은 @SpringBootTest 컨텍스트(고정 포트) 때문에 클래스 전체가 공유한다 →
        // 호출 카운트는 누적이므로 절대값이 아니라 이 테스트 동안의 '증가분'으로 검증한다.
        long pdpBefore = pdpStub.getRequestCount();

        client.get().uri("/api/hello")
                .exchange()
                .expectStatus().isUnauthorized();

        // 인증 실패는 PDP를 부르지 않는다(fail-close).
        assertThat(pdpStub.getRequestCount()).isEqualTo(pdpBefore);
    }

    @Test
    void garbage_token_fails_signature_validation_401() {
        long pdpBefore = pdpStub.getRequestCount();

        client.get().uri("/api/hello")
                .header("Authorization", "Bearer not-a-real-jwt")
                .exchange()
                .expectStatus().isUnauthorized();

        // 서명 검증 실패(JWKS 불일치)도 PDP 호출 전에 차단된다.
        assertThat(pdpStub.getRequestCount()).isEqualTo(pdpBefore);
    }

    @Test
    void real_token_allowed_by_pdp_reaches_backend_with_trust_header() throws Exception {
        String token = issueToken("alice", "alice123");
        // PDP가 ALLOW → 게이트웨이가 백엔드로 전달, 백엔드는 200.
        pdpStub.enqueue(jsonResponse(200, "{\"decision\":\"ALLOW\",\"reason\":\"e2e allow\"}"));
        backendStub.enqueue(new MockResponse().setResponseCode(200).setBody("backend-ok"));

        client.get().uri("/api/hello")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("backend-ok");

        // 백엔드는 게이트웨이가 주입한 신뢰 헤더를 받아야 한다(우회 직접호출 차단의 근거).
        RecordedRequest forwarded = backendStub.takeRequest(5, java.util.concurrent.TimeUnit.SECONDS);
        assertThat(forwarded).isNotNull();
        assertThat(forwarded.getHeader(JwtAuthGlobalFilter.TRUST_HEADER)).isEqualTo(TRUST_SECRET);
    }

    @Test
    void real_token_denied_by_pdp_is_403_and_not_forwarded() throws Exception {
        String token = issueToken("alice", "alice123");
        long backendBefore = backendStub.getRequestCount();
        pdpStub.enqueue(jsonResponse(200,
                "{\"decision\":\"DENY\",\"reason\":\"payroll denied: department must be finance\"}"));

        client.get().uri("/api/payroll")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueMatches(JwtAuthGlobalFilter.DENY_REASON_HEADER, ".*finance.*");

        // DENY면 백엔드로 한 건도 새어 나가지 않는다(증가분 0).
        assertThat(backendStub.getRequestCount()).isEqualTo(backendBefore);
    }

    @Test
    void real_token_but_pdp_failure_fails_closed_to_403() throws Exception {
        String token = issueToken("alice", "alice123");
        long backendBefore = backendStub.getRequestCount();
        // PDP가 503 → 게이트웨이는 "판단 불가"를 DENY로 환산(fail-close)해 403.
        pdpStub.enqueue(new MockResponse().setResponseCode(503));

        client.get().uri("/api/hello")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isForbidden();

        // 장애로 인한 차단도 백엔드로 새지 않는다(증가분 0).
        assertThat(backendStub.getRequestCount()).isEqualTo(backendBefore);
    }

    /** Keycloak password grant로 실제 access token을 발급받는다(realm의 ztg-api 클라이언트). */
    private String issueToken(String username, String password) throws Exception {
        String tokenUri = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080)
                + "/realms/" + REALM + "/protocol/openid-connect/token";
        String form = "grant_type=password"
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + CLIENT_SECRET
                + "&username=" + username
                + "&password=" + password;
        HttpRequest req = HttpRequest.newBuilder(URI.create(tokenUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> resp = HttpClient.newHttpClient()
                .send(req, HttpResponse.BodyHandlers.ofString());
        assertThat(resp.statusCode()).as("token endpoint 응답").isEqualTo(200);
        JsonNode node = json.readTree(resp.body());
        return node.get("access_token").asText();
    }

    private static MockResponse jsonResponse(int code, String body) {
        return new MockResponse()
                .setResponseCode(code)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
