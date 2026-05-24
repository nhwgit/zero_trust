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
 * Phase 1 완료 기준 검증: 유효 토큰 200 / 무·잘못된 토큰 401 / 역할 없으면 403.
 *
 * <p>JwtDecoder는 @MockBean으로 대체한다 — 단위 테스트라 실제 Keycloak(JWKS)에
 * 접속하지 않는다. jwt() post-processor가 검증된 인증을 직접 주입하므로 디코더는 호출되지 않는다.
 */
@WebMvcTest(HelloController.class)
@Import(SecurityConfig.class)
class HelloControllerTest {

    @Autowired
    MockMvc mockMvc;

    @MockBean
    JwtDecoder jwtDecoder;

    @Test
    void hello_without_token_is_401() throws Exception {
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void hello_with_valid_token_is_200() throws Exception {
        mockMvc.perform(get("/api/hello")
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
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_user"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_with_admin_role_is_200() throws Exception {
        mockMvc.perform(get("/api/admin")
                        .with(jwt()
                                .jwt(b -> b.claim("preferred_username", "bob"))
                                .authorities(new SimpleGrantedAuthority("ROLE_admin"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));
    }
}
