package com.ztg.resource;

import java.time.Instant;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Phase 1 — 보호 리소스. 유효한 Keycloak JWT가 있어야 접근 가능하다.
 * 인증 주체(JWT)는 SecurityConfig의 필터 체인이 검증·주입한다.
 */
@RestController
@RequestMapping("/api")
public class HelloController {

    /** 유효한 토큰이면 누구나(any authenticated). 토큰의 신원을 그대로 비춰준다. */
    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "service", "resource-api",
                "message", "hello from zero-trust-gateway",
                "subject", jwt.getSubject(),
                "username", jwt.getClaimAsString("preferred_username"),
                "timestamp", Instant.now().toString());
    }

    /** admin 역할이 있어야 접근(없으면 403). 역할 기반 인가 데모. */
    @GetMapping("/admin")
    public Map<String, Object> admin(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "service", "resource-api",
                "message", "admin-only resource",
                "username", jwt.getClaimAsString("preferred_username"),
                "timestamp", Instant.now().toString());
    }
}
