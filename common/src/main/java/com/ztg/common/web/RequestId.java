package com.ztg.common.web;

/**
 * 요청 추적(분산 trace)의 상관 키에 대한 공용 상수.
 * 순수 상수만 담아 servlet/slf4j 의존 없이 리액티브 게이트웨이와 서블릿 서비스가 함께 참조한다.
 */
public final class RequestId {

    /** 서비스 경계를 넘어 전파되는 요청 추적 ID 헤더. 없으면 진입점이 생성한다. */
    public static final String HEADER = "X-Request-Id";

    /** 로그 패턴(%X{requestId})이 참조하는 MDC 키. 한 요청의 모든 로그를 이 값으로 묶는다. */
    public static final String MDC_KEY = "requestId";

    private RequestId() {
    }
}
