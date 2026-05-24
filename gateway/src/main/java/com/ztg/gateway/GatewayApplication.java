package com.ztg.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Zero Trust Access Gateway — DP/PEP 진입점.
 *
 * <p>모든 외부 트래픽이 이 게이트웨이를 통과한다. 여기서 JWT를 검증(PEP)하고,
 * 통과한 요청에만 내부 신뢰 헤더를 실어 {@code resource-api}로 전달한다.
 */
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
