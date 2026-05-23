package com.ztg.resource;

import java.time.Instant;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Phase 0 동작 확인용 엔드포인트. 아직 인증을 요구하지 않는다.
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public Map<String, Object> hello() {
        return Map.of(
                "service", "resource-api",
                "message", "hello from zero-trust-gateway",
                "timestamp", Instant.now().toString());
    }
}
