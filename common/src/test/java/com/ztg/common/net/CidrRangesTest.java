package com.ztg.common.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * IP/CIDR 매칭의 단위 검증 — 경계(프리픽스 끝), 주소 패밀리 혼합, 잘못된 설정의 fail-fast까지.
 * XFF 채택(게이트웨이)과 에지 차단 제외(PIP)가 이 판정 하나에 걸려 있으므로 매칭이 정확해야 한다.
 */
class CidrRangesTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static CidrRanges ranges(String... entries) {
        return CidrRanges.parse(List.of(entries), "test-setting");
    }

    @Test
    void plain_ip_entry_matches_only_that_address() {
        CidrRanges ranges = ranges("203.0.113.7");

        assertThat(ranges.contains(ip("203.0.113.7"))).isTrue();
        assertThat(ranges.contains(ip("203.0.113.8"))).isFalse();
    }

    @Test
    void loopback_cidr_covers_whole_127_range() {
        CidrRanges ranges = ranges("127.0.0.0/8");

        assertThat(ranges.contains(ip("127.0.0.1"))).isTrue();
        assertThat(ranges.contains(ip("127.255.255.254"))).isTrue();
        assertThat(ranges.contains(ip("128.0.0.1"))).isFalse();
    }

    @Test
    void non_octet_aligned_prefix_matches_partial_byte() {
        // /12는 두 번째 바이트의 상위 4비트까지만 비교한다(172.16.0.0 ~ 172.31.255.255).
        CidrRanges ranges = ranges("172.16.0.0/12");

        assertThat(ranges.contains(ip("172.31.9.9"))).isTrue();
        assertThat(ranges.contains(ip("172.32.0.1"))).isFalse();
    }

    @Test
    void ipv6_entry_does_not_match_ipv4_address() {
        CidrRanges ranges = ranges("::1/128");

        assertThat(ranges.contains(ip("::1"))).isTrue();
        assertThat(ranges.contains(ip("127.0.0.1"))).isFalse();
    }

    @Test
    void empty_list_matches_nothing() {
        assertThat(ranges().contains(ip("127.0.0.1"))).isFalse();
    }

    @Test
    void hostname_entry_fails_fast_with_setting_name() {
        // 호스트명은 DNS 조회로 엉뚱한 주소를 매칭하게 될 수 있어 기동 시점에 거부한다.
        assertThatThrownBy(() -> CidrRanges.parse(List.of("proxy-host"), "ztg.pip.edge-block-exempt"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ztg.pip.edge-block-exempt");
    }

    @Test
    void out_of_range_prefix_fails_fast() {
        assertThatThrownBy(() -> ranges("10.0.0.0/33"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void contains_literal_matches_string_ip_without_dns() {
        CidrRanges ranges = ranges("10.0.0.0/8");

        assertThat(ranges.containsLiteral("10.1.2.3")).isTrue();
        assertThat(ranges.containsLiteral("11.0.0.1")).isFalse();
    }

    @Test
    void contains_literal_treats_non_literal_as_no_match() {
        CidrRanges ranges = ranges("10.0.0.0/8");

        assertThat(ranges.containsLiteral("some-host")).isFalse();
        assertThat(ranges.containsLiteral(null)).isFalse();
        assertThat(ranges.containsLiteral(" ")).isFalse();
    }
}
