package com.ztg.resource;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Phase 1+2 완료 기준 검증: 유효 토큰 200 / 무·잘못된 토큰 401 / 역할 없으면 403.
 * 추가로 Phase 2: 게이트웨이 신뢰 헤더가 없으면(우회 직접호출) 유효 토큰이어도 403.
 *
 * <p>JwtDecoder는 @MockBean으로 대체한다 — 단위 테스트라 실제 Keycloak(JWKS)에
 * 접속하지 않는다. jwt() post-processor가 검증된 인증을 직접 주입하므로 디코더는 호출되지 않는다.
 * 정상 경로 요청은 게이트웨이가 주입했을 신뢰 헤더({@code X-Gateway-Auth})를 함께 보낸다.
 */
@WebMvcTest(HelloController.class)
@Import(SecurityConfig.class)
class HelloControllerTest {

    /** 테스트 컨텍스트의 ztg.resource.trust-secret 기본값과 동일. */
    private static final String TRUST = "ztg-gateway-trust-secret";

    @Autowired
    MockMvc mockMvc;

    @MockBean
    JwtDecoder jwtDecoder;

    @Test
    void hello_without_token_is_401() throws Exception {
        mockMvc.perform(get("/api/hello").header(GatewayTrustFilter.TRUST_HEADER, TRUST))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void hello_with_valid_token_is_200() throws Exception {
        mockMvc.perform(get("/api/hello")
                        .header(GatewayTrustFilter.TRUST_HEADER, TRUST)
                        .with(jwt()
                                .jwt(b -> b.claim("preferred_username", "alice"))
                                .authorities(new SimpleGrantedAuthority("ROLE_user"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("resource-api"))
                .andExpect(jsonPath("$.username").value("alice"));
    }

    @Test
    void admin_without_admin_role_is_403() throws Exception {
        mockMvc.perform(get("/api/admin")
                        .header(GatewayTrustFilter.TRUST_HEADER, TRUST)
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_user"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_with_admin_role_is_200() throws Exception {
        mockMvc.perform(get("/api/admin")
                        .header(GatewayTrustFilter.TRUST_HEADER, TRUST)
                        .with(jwt()
                                .jwt(b -> b.claim("preferred_username", "bob"))
                                .authorities(new SimpleGrantedAuthority("ROLE_admin"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));
    }

    /** Phase 2: 게이트웨이를 우회한 직접 호출(신뢰 헤더 없음)은 유효 토큰이어도 403으로 막힌다. */
    @Test
    void bypass_without_trust_header_is_403() throws Exception {
        mockMvc.perform(get("/api/hello")
                        .with(jwt()
                                .jwt(b -> b.claim("preferred_username", "alice"))
                                .authorities(new SimpleGrantedAuthority("ROLE_user"))))
                .andExpect(status().isForbidden());
    }

    /** Phase 2: 신뢰 헤더 값이 틀리면(위조 시도) 차단된다. */
    @Test
    void bypass_with_wrong_trust_header_is_403() throws Exception {
        mockMvc.perform(get("/api/hello")
                        .header(GatewayTrustFilter.TRUST_HEADER, "wrong-secret")
                        .with(jwt()
                                .jwt(b -> b.claim("preferred_username", "alice"))
                                .authorities(new SimpleGrantedAuthority("ROLE_user"))))
                .andExpect(status().isForbidden());
    }
}
