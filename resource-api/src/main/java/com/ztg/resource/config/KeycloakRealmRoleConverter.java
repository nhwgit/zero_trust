package com.ztg.resource.config;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Keycloak realm 역할 → Spring Security 권한 변환기.
 *
 * <p>Keycloak은 realm 역할을 토큰의 {@code realm_access.roles} 배열에 담는다:
 * <pre>{ "realm_access": { "roles": ["user", "admin"] } }</pre>
 * Spring의 기본 변환기는 {@code scope}/{@code scp}만 보므로, 역할 기반 인가
 * ({@code hasRole("admin")})를 쓰려면 직접 매핑해야 한다.
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess == null) {
            return List.of();
        }
        Object roles = realmAccess.get("roles");
        if (!(roles instanceof Collection<?> roleList)) {
            return List.of();
        }
        // hasRole("admin")은 "ROLE_admin" 권한을 요구하므로 접두어를 붙인다.
        return roleList.stream()
                .map(Object::toString)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toUnmodifiableList());
    }
}
