package com.ztg.pdp;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/** Policy Decision Point — 정책 평가의 두뇌. */
@SpringBootApplication
public class PdpApplication {
    public static void main(String[] args) {
        SpringApplication.run(PdpApplication.class, args);
    }

    /** 시간 기반 정책용 시계 — 테스트에서 고정 Clock을 주입해 결정적으로 검증하기 위해 빈으로 분리. */
    @Bean
    Clock clock() {
        return Clock.systemDefaultZone();
    }
}
