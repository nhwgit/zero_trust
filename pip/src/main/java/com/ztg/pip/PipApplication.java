package com.ztg.pip;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Policy Information Point — 주체의 맥락/속성을 PDP에 제공하는 내부 서비스. */
@SpringBootApplication
public class PipApplication {
    public static void main(String[] args) {
        SpringApplication.run(PipApplication.class, args);
    }
}
