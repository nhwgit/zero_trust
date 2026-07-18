package com.ztg.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * IP/CIDR 신뢰 판정의 단위 검증 — 경계(프리픽스 끝), 주소 패밀리 혼합, 잘못된 설정의
 * fail-fast까지. XFF 채택 여부는 이 판정 하나에 걸려 있으므로 매칭이 정확해야 한다.
 */
class TrustedProxiesTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void plain_ip_entry_matches_only_that_address() {
        TrustedProxies proxies = TrustedProxies.fromCidrs(List.of("203.0.113.7"));

        assertThat(proxies.isTrusted(ip("203.0.113.7"))).isTrue();
        assertThat(proxies.isTrusted(ip("203.0.113.8"))).isFalse();
    }

    @Test
    void loopback_cidr_covers_whole_127_range() {
        TrustedProxies proxies = TrustedProxies.fromCidrs(List.of("127.0.0.0/8"));

        assertThat(proxies.isTrusted(ip("127.0.0.1"))).isTrue();
        assertThat(proxies.isTrusted(ip("127.255.255.254"))).isTrue();
        assertThat(proxies.isTrusted(ip("128.0.0.1"))).isFalse();
    }

    @Test
    void non_octet_aligned_prefix_matches_partial_byte() {
        // /12는 두 번째 바이트의 상위 4비트까지만 비교한다(172.16.0.0 ~ 172.31.255.255).
        TrustedProxies proxies = TrustedProxies.fromCidrs(List.of("172.16.0.0/12"));

        assertThat(proxies.isTrusted(ip("172.31.9.9"))).isTrue();
        assertThat(proxies.isTrusted(ip("172.32.0.1"))).isFalse();
    }

    @Test
    void ipv6_entry_does_not_match_ipv4_address() {
        TrustedProxies proxies = TrustedProxies.fromCidrs(List.of("::1/128"));

        assertThat(proxies.isTrusted(ip("::1"))).isTrue();
        assertThat(proxies.isTrusted(ip("127.0.0.1"))).isFalse();
    }

    @Test
    void empty_list_trusts_nobody() {
        TrustedProxies proxies = TrustedProxies.fromCidrs(List.of());

        assertThat(proxies.isTrusted(ip("127.0.0.1"))).isFalse();
    }

    @Test
    void hostname_entry_fails_fast() {
        // 호스트명은 DNS 조회로 엉뚱한 주소를 신뢰하게 될 수 있어 기동 시점에 거부한다.
        assertThatThrownBy(() -> TrustedProxies.fromCidrs(List.of("proxy-host")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void out_of_range_prefix_fails_fast() {
        assertThatThrownBy(() -> TrustedProxies.fromCidrs(List.of("10.0.0.0/33")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
