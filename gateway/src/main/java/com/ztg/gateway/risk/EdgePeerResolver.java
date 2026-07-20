package com.ztg.gateway.risk;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.springframework.http.server.reactive.AbstractServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import com.ztg.common.net.CidrRanges;
import com.ztg.gateway.config.ProxyProtocolProperties;

import reactor.netty.http.server.HttpServerRequest;

/**
 * 이 연결의 "에지 피어" 산출 — 진짜 에지(LB 앞, 커널 XDP가 패킷을 보는 자리)에서 이 연결의 소스로
 * 보이는 주소. PROXY protocol이 꺼져 있으면(기본) 소켓 피어 그대로다. 켜면 소켓 피어가 신뢰
 * 발신(LB) 목록에 들 때만 PP가 광고한 원 클라이언트를 인정한다 — PP 헤더도 자기 신고 값이라
 * XFF와 같은 원칙으로 발신을 검증하지 않으면 직결 클라이언트가 위조 PP로 축을 오염시킬 수 있다.
 */
@Component
public class EdgePeerResolver {

    private final boolean proxyProtocolEnabled;
    private final CidrRanges trustedSenders;

    public EdgePeerResolver(ProxyProtocolProperties properties) {
        this.proxyProtocolEnabled = properties.enabled();
        this.trustedSenders = CidrRanges.parse(properties.trustedSenders(),
                "ztg.gateway.proxy-protocol.trusted-senders");
    }

    /**
     * 에지 피어 주소. PP off: 소켓 피어(= remoteAddress) 그대로. PP on: 소켓 피어가 신뢰 발신이면
     * 광고된 주소(원 클라이언트), 아니면 소켓 피어(위조 PP 기각). 소켓 피어를 확인 못 하면
     * 미상({@code null}) — 검증 불가한 광고 값을 채택하지 않는다(fail-safe).
     */
    public InetAddress resolve(ServerHttpRequest request) {
        InetSocketAddress advertised = request.getRemoteAddress();
        if (!proxyProtocolEnabled) {
            return advertised != null ? advertised.getAddress() : null;
        }
        InetSocketAddress socket = connectionPeer(request);
        if (socket == null) {
            return null;
        }
        if (advertised != null && trustedSenders.contains(socket.getAddress())) {
            return advertised.getAddress();
        }
        return socket.getAddress();
    }

    /** 실제 TCP 소켓 피어. PP가 켜지면 remoteAddress는 광고 값으로 바뀌므로 네이티브 연결 정보에서 얻는다. */
    protected InetSocketAddress connectionPeer(ServerHttpRequest request) {
        if (request instanceof AbstractServerHttpRequest nativeAccessor
                && nativeAccessor.getNativeRequest() instanceof HttpServerRequest reactorRequest
                && reactorRequest.connectionRemoteAddress() instanceof InetSocketAddress socket) {
            return socket;
        }
        return null;
    }
}
