package com.ztg.common.web;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.MDC;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 서블릿 서비스의 진입 필터 — 요청 추적 ID를 MDC에 실어 그 요청의 모든 로그를 같은 키로 묶는다.
 * 들어온 {@code X-Request-Id}를 잇고 없으면 생성하며, 응답 헤더로도 돌려준다.
 * 각 서비스가 {@code HIGHEST_PRECEDENCE}로 등록해 보안 필터의 거부(401/403) 로그까지 같은 ID를 갖게 한다.
 */
public class RequestIdFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String requestId = resolve(request);
        MDC.put(RequestId.MDC_KEY, requestId);
        if (response instanceof HttpServletResponse http) {
            http.setHeader(RequestId.HEADER, requestId);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            // finally에서 MDC 정리 — 스레드 풀 재사용 시 다음 요청으로 ID 누수 방지.
            MDC.remove(RequestId.MDC_KEY);
        }
    }

    private static String resolve(ServletRequest request) {
        if (request instanceof HttpServletRequest http) {
            String incoming = http.getHeader(RequestId.HEADER);
            if (incoming != null && !incoming.isBlank()) {
                return incoming;
            }
        }
        return UUID.randomUUID().toString();
    }
}
