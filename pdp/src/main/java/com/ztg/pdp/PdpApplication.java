package com.ztg.pdp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Policy Decision Point — 정책 평가의 두뇌. 시각 입력은 게이트웨이 관측값을 쓰므로 자체 시계가 없다. */
@SpringBootApplication
public class PdpApplication {
    public static void main(String[] args) {
        SpringApplication.run(PdpApplication.class, args);
    }
}
