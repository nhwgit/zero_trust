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
 * 서블릿 서비스의 진입 필터 — 요청 추적 ID를 MDC에 실어 그 요청의 <b>모든 로그</b>를 같은 키로 묶는다.
 *
 * <p>흐름: 들어온 {@code X-Request-Id}가 있으면 잇고(게이트웨이/상위 서비스가 전파한 값), 없으면
 * 새로 생성한다. 이 값을 {@link MDC}({@link RequestId#MDC_KEY})에 넣어 로그 패턴
 * {@code %X{requestId}}가 자동으로 찍게 하고, 응답 헤더로도 돌려준다. 처리 후에는 스레드 풀
 * 재사용으로 ID가 다음 요청에 새지 않도록 {@code finally}에서 반드시 비운다.
 *
 * <p>설계 메모:
 * <ul>
 *   <li><b>공용 위치(common)</b>: pdp/pip/resource-api가 토씨 하나까지 같은 전파 규약(헤더명·MDC키·
 *       생성정책)을 쓰도록 한 곳에 둔다. servlet/slf4j는 {@code compileOnly}라 리액티브 게이트웨이로
 *       새지 않는다.</li>
 *   <li><b>최우선 등록</b>: 각 서비스가 {@code HIGHEST_PRECEDENCE}로 등록해 보안/신뢰헤더 필터의
 *       거부(401/403) 로그까지 같은 ID를 갖게 한다.</li>
 *   <li><b>분산 추적</b>: 게이트웨이가 만든 ID가 PDP→PIP까지 헤더로 흐르며, 각 서비스 로그가 동일
 *       ID로 상관된다. 한 요청의 경로를 로그만으로 추적할 수 있다.</li>
 * </ul>
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
            // 스레드 풀 재사용 — 다음 요청으로 ID가 새지 않도록 항상 비운다.
            MDC.remove(RequestId.MDC_KEY);
        }
    }

    /** 들어온 {@code X-Request-Id}를 잇거나, 없으면 새로 생성한다(분산 추적의 상관 키). */
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
