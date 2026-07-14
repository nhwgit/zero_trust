package com.ztg.resource.filter;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 게이트웨이(PEP) 경유를 강제하는 필터 — 우회 직접호출 차단.
 *
 * <p>resource-api는 게이트웨이가 주입한 내부 신뢰 헤더({@code X-Gateway-Auth})가
 * 약속된 공유 비밀과 일치할 때만 요청을 받아들인다. 헤더가 없거나 값이 틀리면
 * (= 게이트웨이를 우회한 직접 호출이면) 유효한 JWT를 들고 와도 <b>403</b>으로 막는다.
 *
 * <p>설계 메모:
 * <ul>
 *   <li><b>defense-in-depth</b>: 이 필터는 JWT 검증을 대체하지 않는다. resource-api는
 *       여전히 토큰을 스스로 검증하고({@link com.ztg.resource.config.SecurityConfig}), 그 <i>앞단</i>에서 "PEP를
 *       거쳤는가"를 추가로 확인한다. 두 관문을 모두 통과해야 한다.</li>
 *   <li><b>정적 공유 비밀의 한계</b>: 비밀을 아는 주체만 헤더를 위조할 수 있다는 전제다.
 *       데모용 단순화이며, mtls 프로파일에선 mTLS(상호 TLS)가 출처를 암호학적으로 증명해 대체한다.</li>
 *   <li><b>타이밍 안전 비교</b>: 비밀 비교는 {@link MessageDigest#isEqual}로 상수시간 비교한다.</li>
 *   <li><b>fail-close</b>: 비밀이 비어 있게 설정되면 모든 요청을 막는다(열어두지 않는다).</li>
 * </ul>
 */
public class GatewayTrustFilter extends OncePerRequestFilter {

    public static final String TRUST_HEADER = "X-Gateway-Auth";

    private final byte[] expectedSecret;

    public GatewayTrustFilter(String trustSecret) {
        this.expectedSecret = trustSecret == null ? new byte[0]
                : trustSecret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 관측 엔드포인트({@code /actuator/**})는 PEP를 거치지 않고 Prometheus가 직접 스크랩하므로
     * 신뢰 헤더 검사에서 제외한다. 보호 대상 비즈니스 API({@code /api/**})에만 PEP 경유를 강제한다.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/actuator/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String presented = request.getHeader(TRUST_HEADER);
        if (!matches(presented)) {
            // fail-close: PEP 경유 증거가 없으면 인증 토큰 검증 이전에 차단한다.
            // sendError()는 컨테이너가 /error로 재디스패치하는데, 그 경로도 인증을 요구해
            // 403이 401로 덮어써진다. setStatus로 직접 응답해 재디스패치를 피한다.
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
