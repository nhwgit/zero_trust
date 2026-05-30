package com.ztg.pip.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import com.ztg.common.web.RequestIdFilter;

/**
 * 요청 추적 ID 필터를 체인 최우선으로 등록한다 — PDP가 전파한 {@code X-Request-Id}를
 * MDC에 실어 이 서비스의 모든 로그가 같은 ID로 상관되게 한다(분산 추적).
 */
@Configuration
public class WebConfig {

    @Bean
    FilterRegistrationBean<RequestIdFilter> requestIdFilter() {
        FilterRegistrationBean<RequestIdFilter> reg = new FilterRegistrationBean<>(new RequestIdFilter());
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }
}
