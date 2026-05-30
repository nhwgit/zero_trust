package com.ztg.resource.web;

import java.time.Instant;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(HelloController.class);

    /** 유효한 토큰이면 누구나(any authenticated). 토큰의 신원을 그대로 비춰준다. */
    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        // 게이트웨이가 전파한 요청ID(MDC)가 이 백엔드 로그에도 찍혀 같은 요청으로 상관된다(분산 추적).
        log.info("serving /api/hello for subject={}", jwt.getClaimAsString("preferred_username"));
        return Map.of(
                "service", "resource-api",
                "message", "hello from zero-trust-gateway",
                "subject", jwt.getSubject(),
                "username", jwt.getClaimAsString("preferred_username"),
                "timestamp", Instant.now().toString());
    }

    /**
     * 급여 리소스. resource-api 자체는 "인증됨"만 요구하고, <b>누가 언제 어떤 디바이스로</b>
     * 접근 가능한지(부서/업무시간/디바이스)는 게이트웨이 앞단의 PDP가 ABAC로 판단한다.
     * 즉 이 핸들러에 도달했다는 것은 PDP가 이미 ALLOW했다는 뜻이다(관심사 분리).
     */
    @GetMapping("/payroll")
    public Map<String, Object> payroll(@AuthenticationPrincipal Jwt jwt) {
        log.info("serving /api/payroll for subject={}", jwt.getClaimAsString("preferred_username"));
        return Map.of(
                "service", "resource-api",
                "message", "payroll data (PDP-authorized)",
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
