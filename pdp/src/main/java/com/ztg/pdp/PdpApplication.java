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

    /**
     * 업무시간 등 시간 기반 정책이 쓰는 시계. 빈으로 분리해 테스트에서 고정 Clock을 주입할 수 있게 한다
     * (실시간에 의존하면 시간 정책을 결정적으로 검증할 수 없다).
     */
    @Bean
    Clock clock() {
        return Clock.systemDefaultZone();
    }
}
