package com.ztg.gateway;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

/**
 * Zero Trust Access Gateway — DP/PEP 진입점. 모든 외부 트래픽이 여기서 JWT 검증(PEP)을 거쳐
 * 내부 신뢰 헤더와 함께 {@code resource-api}로 전달된다.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    /** 시각 기반 위험 신호용 시계 — 테스트에서 고정 시계로 대체할 수 있게 빈으로 분리. */
    @Bean
    Clock clock() {
        return Clock.systemDefaultZone();
    }
}
