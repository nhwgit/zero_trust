package com.ztg.pip;

import java.time.Clock;
import java.time.ZoneId;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

/** Policy Information Point — 주체의 맥락/속성을 PDP에 제공하는 내부 서비스. */
@SpringBootApplication
@ConfigurationPropertiesScan
public class PipApplication {
    public static void main(String[] args) {
        SpringApplication.run(PipApplication.class, args);
    }

    /**
     * out-of-band(L4 재평가) 시각 신호용 시계 — 요청 경로의 hour는 게이트웨이 관측값을 쓰지만
     * 이 경로엔 요청이 없어 자체 시계가 불가피하다. 존을 게이트웨이와 같은 값으로 고정해
     * 판정 좌표를 맞춘다. 잘못된 존 이름은 기동 실패(fail-fast).
     */
    @Bean
    Clock clock(@Value("${ztg.pip.zone:Asia/Seoul}") String zone) {
        return Clock.system(ZoneId.of(zone));
    }
}
