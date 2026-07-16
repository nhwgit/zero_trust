package com.ztg.gateway;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

/**
 * Zero Trust Access Gateway — DP/PEP 진입점.
 *
 * <p>모든 외부 트래픽이 이 게이트웨이를 통과한다. 여기서 JWT를 검증(PEP)하고,
 * 통과한 요청에만 내부 신뢰 헤더를 실어 {@code resource-api}로 전달한다.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    /**
     * 요청 시각(hour-of-day) 위험 신호를 산출하는 시계. 빈으로 분리해 테스트에서 고정 시계로
     * 대체할 수 있게 한다(업무시간 외 신호의 결정적 검증). PDP의 clock 빈과 같은 배치.
     */
    @Bean
    Clock clock() {
        return Clock.systemDefaultZone();
    }
}
