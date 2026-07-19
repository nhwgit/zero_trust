package com.ztg.gateway;

import java.time.Clock;
import java.time.ZoneId;

import org.springframework.beans.factory.annotation.Value;
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

    /**
     * 시각 기반 위험 신호용 시계. 존은 호스트 TZ가 아니라 설정으로 고정한다 — hour-of-day가 캐시 키와
     * off-hours 판정에 들어가므로, 다중 GW의 존이 갈리면 같은 순간의 판정·키가 노드마다 갈린다.
     * 잘못된 존 이름은 기동 실패(fail-fast).
     */
    @Bean
    Clock clock(@Value("${ztg.gateway.zone:Asia/Seoul}") String zone) {
        return Clock.system(ZoneId.of(zone));
    }
}
