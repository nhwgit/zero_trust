package com.ztg.gateway;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import org.junit.jupiter.api.Test;

import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.ProxyProtocolSupportType;

/**
 * EdgePeerResolver가 딛고 선 reactor-netty PROXY protocol 전제의 고정 테스트 —
 * PP 헤더가 오면 remoteAddress()는 광고 주소로 바뀌고 connectionRemoteAddress()는 실제 소켓 피어로
 * 남으며, AUTO 모드에서 PP 없는 직결 연결은 종전 그대로다(직결 무회귀의 서버 측 전제).
 */
class ProxyProtocolWireTest {

    @Test
    void pp_header_splits_advertised_and_socket_addresses() throws Exception {
        assertThat(exchange("PROXY TCP4 203.0.113.7 10.0.0.1 40000 8080\r\n"))
                .contains("203.0.113.7|127.0.0.1");
    }

    @Test
    void plain_connection_keeps_socket_peer_on_both() throws Exception {
        assertThat(exchange("")).contains("127.0.0.1|127.0.0.1");
    }

    /** PP(AUTO) 서버를 임시 포트에 띄우고 raw 소켓으로 [PP헤더+]HTTP를 보내 두 주소를 응답으로 받는다. */
    private static String exchange(String ppHeader) throws Exception {
        DisposableServer server = HttpServer.create()
                .host("127.0.0.1")
                .port(0)
                .proxyProtocol(ProxyProtocolSupportType.AUTO)
                .handle((req, res) -> res.sendString(Mono.just(
                        ip(req.remoteAddress()) + "|" + ip(req.connectionRemoteAddress()))))
                .bindNow();
        try (Socket socket = new Socket("127.0.0.1", server.port())) {
            OutputStream out = socket.getOutputStream();
            out.write((ppHeader + "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").getBytes(US_ASCII));
            out.flush();
            return new String(socket.getInputStream().readAllBytes(), US_ASCII);
        } finally {
            server.disposeNow();
        }
    }

    private static String ip(SocketAddress address) {
        return address instanceof InetSocketAddress inet ? inet.getAddress().getHostAddress() : "?";
    }
}
