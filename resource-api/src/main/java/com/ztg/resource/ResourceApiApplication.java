package com.ztg.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 보호 대상 백엔드 서비스 — Keycloak JWT를 검증하는 Resource Server로 보호된다.
 */
@SpringBootApplication
public class ResourceApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceApiApplication.class, args);
    }
}
