package com.ztg.resource.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * realm_access.roles → ROLE_* 매핑 단위 테스트. (Resource Server의 핵심 변환 로직)
 */
class KeycloakRealmRoleConverterTest {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    private Jwt jwtWithClaims(Map<String, Object> claims) {
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("alg", "RS256"), claims);
    }

    @Test
    void maps_realm_roles_to_prefixed_authorities() {
        Jwt jwt = jwtWithClaims(Map.of(
                "sub", "u1",
                "realm_access", Map.of("roles", List.of("user", "admin"))));

        assertThat(converter.convert(jwt))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_user", "ROLE_admin");
    }

    @Test
    void returns_empty_when_realm_access_absent() {
        Jwt jwt = jwtWithClaims(Map.of("sub", "u1"));
        assertThat(converter.convert(jwt)).isEmpty();
    }
}
