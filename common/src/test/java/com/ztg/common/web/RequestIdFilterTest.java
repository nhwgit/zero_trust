package com.ztg.common.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

/**
 * RequestIdFilter 단위 검증 — 분산 추적의 핵심 규약(생성/전파/응답에코/MDC 정리)을 못박는다.
 */
class RequestIdFilterTest {

    private final RequestIdFilter filter = new RequestIdFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void generates_id_when_absent_and_echoes_to_response() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> seenInChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> seenInChain.set(MDC.get(RequestId.MDC_KEY));

        filter.doFilter(request, response, chain);

        // 체인 실행 중 MDC에 ID가 있고, 같은 값이 응답 헤더로 돌아간다.
        assertThat(seenInChain.get()).isNotBlank();
        assertThat(response.getHeader(RequestId.HEADER)).isEqualTo(seenInChain.get());
    }

    @Test
    void propagates_incoming_request_id() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(RequestId.HEADER, "trace-xyz");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> seenInChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> seenInChain.set(MDC.get(RequestId.MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(seenInChain.get()).isEqualTo("trace-xyz");
        assertThat(response.getHeader(RequestId.HEADER)).isEqualTo("trace-xyz");
    }

    @Test
    void clears_mdc_after_request_even_on_error() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain failing = (req, res) -> {
            throw new ServletException("boom");
        };

        assertThatThrownBy(() -> filter.doFilter(request, response, failing))
                .isInstanceOf(ServletException.class);

        // 스레드 풀 재사용 시 다음 요청으로 ID가 새지 않도록 finally에서 비워졌는지.
        assertThat(MDC.get(RequestId.MDC_KEY)).isNull();
    }
}
