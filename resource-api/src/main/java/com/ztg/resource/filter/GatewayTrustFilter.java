package com.ztg.resource.filter;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ztg.common.web.GatewayTrust;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 게이트웨이(PEP) 경유를 강제하는 필터 — 신뢰 헤더가 공유 비밀과 다르면 유효한 JWT라도 403(우회 직접호출 차단).
 * JWT 검증을 대체하지 않는 앞단 관문이며(defense-in-depth), 비밀이 비어 있으면 모든 요청을 막는다(fail-close).
 * 정적 공유 비밀은 데모용 단순화 — mtls 프로파일에선 mTLS가 출처 증명을 대체한다.
 */
public class GatewayTrustFilter extends OncePerRequestFilter {

    public static final String TRUST_HEADER = GatewayTrust.HEADER;

    private final byte[] expectedSecret;

    public GatewayTrustFilter(String trustSecret) {
        this.expectedSecret = trustSecret == null ? new byte[0]
                : trustSecret.getBytes(StandardCharsets.UTF_8);
    }

    /** {@code /actuator/**}는 Prometheus가 PEP 없이 직접 스크랩하므로 신뢰 헤더 검사에서 제외한다. */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String presented = request.getHeader(TRUST_HEADER);
        if (!matches(presented)) {
            // sendError()는 /error 재디스패치로 403이 401로 덮어써진다 — setStatus로 직접 응답.
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("must traverse the gateway (PEP)");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean matches(String presented) {
        if (presented == null || expectedSecret.length == 0) {
            return false;
        }
        return MessageDigest.isEqual(expectedSecret, presented.getBytes(StandardCharsets.UTF_8));
    }
}
