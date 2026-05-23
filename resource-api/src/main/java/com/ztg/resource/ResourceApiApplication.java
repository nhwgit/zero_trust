package com.ztg.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 보호 대상 백엔드 서비스.
 * Phase 0에서는 인증 없이 동작을 확인하고, Phase 1에서 JWT Resource Server로 보호한다.
 */
@SpringBootApplication
public class ResourceApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceApiApplication.class, args);
    }
}
