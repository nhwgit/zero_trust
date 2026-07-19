package com.ztg.resource.config;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Keycloak realm 역할({@code realm_access.roles}) → Spring Security 권한 변환기.
 * Spring 기본 변환기는 {@code scope}/{@code scp}만 보므로 {@code hasRole("admin")}을 쓰려면 직접 매핑해야 한다.
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
                .map(role -> "ROLE_" + role)
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }
}
