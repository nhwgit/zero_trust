package com.ztg.gateway.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.server.reactive.AbstractServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import com.ztg.gateway.config.ProxyProtocolProperties;

import reactor.netty.http.server.HttpServerRequest;

/**
 * 에지 피어 산출 규칙 검증 — PP 게이트 off/on × 발신 신뢰/비신뢰 × 소켓 피어 미상.
 * PP가 켜지면 remoteAddress는 광고 값이므로 mock의 remoteAddress에 광고 주소를 싣고,
 * 실제 소켓 피어는 seam(connectionPeer)을 스텁해 분리 주입한다.
 */
class EdgePeerResolverTest {

    private static final List<String> LB_RANGE = List.of("172.28.0.0/16");

    private static EdgePeerResolver ppResolver(InetSocketAddress socketPeer) {
        return new EdgePeerResolver(new ProxyProtocolProperties(true, LB_RANGE)) {
            @Override
            protected InetSocketAddress connectionPeer(ServerHttpRequest request) {
                return socketPeer;
            }
        };
    }

    private static ServerHttpRequest requestWithRemote(String ip) {
        return MockServerHttpRequest.get("/api/hello")
                .remoteAddress(new InetSocketAddress(ip, 40000)).build();
    }

    @Test
    void gate_off_uses_remote_address_as_is() {
        EdgePeerResolver resolver = new EdgePeerResolver(new ProxyProtocolProperties(false, List.of()));

        assertThat(resolver.resolve(requestWithRemote("198.51.100.9")).getHostAddress())
                .isEqualTo("198.51.100.9");
    }

    @Test
    void trusted_sender_pp_advertised_address_becomes_edge_peer() {
        EdgePeerResolver resolver = ppResolver(new InetSocketAddress("172.28.0.2", 55555));

        assertThat(resolver.resolve(requestWithRemote("203.0.113.7")).getHostAddress())
                .isEqualTo("203.0.113.7");
    }

    @Test
    void untrusted_sender_pp_is_rejected_and_socket_peer_is_used() {
        // 직결 클라이언트가 PP 헤더를 위조해도 발신(소켓 피어)이 LB 대역이 아니면 광고 값은 버려진다.
        EdgePeerResolver resolver = ppResolver(new InetSocketAddress("198.51.100.9", 55555));

        assertThat(resolver.resolve(requestWithRemote("10.1.2.3")).getHostAddress())
                .isEqualTo("198.51.100.9");
    }

    @Test
    void decorator_wrapped_request_still_reaches_native_socket_peer() {
        // 실제 필터 체인에선 Spring Security 방화벽이 요청을 데코레이터로 감싼 채 전달한다 —
        // 위임 체인을 벗기지 못하면 소켓 피어 미상(fail-safe null)으로 오판해 네트워크 축이 사라진다.
        EdgePeerResolver resolver = new EdgePeerResolver(new ProxyProtocolProperties(true, LB_RANGE));
        HttpServerRequest reactorRequest = mock(HttpServerRequest.class);
        when(reactorRequest.connectionRemoteAddress()).thenReturn(new InetSocketAddress("172.28.0.2", 55555));
        AbstractServerHttpRequest nativeHolder = mock(AbstractServerHttpRequest.class);
        when(nativeHolder.getNativeRequest()).thenReturn(reactorRequest);
        when(nativeHolder.getRemoteAddress()).thenReturn(new InetSocketAddress("203.0.113.7", 40000));

        ServerHttpRequest decorated = new ServerHttpRequestDecorator(new ServerHttpRequestDecorator(nativeHolder));

        assertThat(resolver.resolve(decorated).getHostAddress()).isEqualTo("203.0.113.7");
    }

    @Test
    void unknown_socket_peer_with_gate_on_yields_no_edge_peer() {
        // 발신을 확인 못 하면 검증 불가한 광고 값을 채택하지 않는다(fail-safe: 축 부재 = 무가중).
        EdgePeerResolver resolver = ppResolver(null);

        assertThat(resolver.resolve(requestWithRemote("10.1.2.3"))).isNull();
    }
}
