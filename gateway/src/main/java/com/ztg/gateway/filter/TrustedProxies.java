package com.ztg.gateway.filter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * 신뢰 프록시 판정 — IP/CIDR 목록을 파싱해 "이 소켓 원격주소의 XFF를 믿어도 되는가"에 답한다.
 *
 * <p>게이트웨이는 최외곽 진입점이라 {@code X-Forwarded-For}는 발신자가 임의로 쓸 수 있는
 * 자기 신고 값이다. 소켓 원격주소가 이 목록에 드는 발신(우리가 세운 프록시/LB)일 때만
 * XFF를 인정해야 위조 XFF로 ip-change 신호를 회피하거나 캐시·PIP 상태를 오염시키는 경로가
 * 막힌다. 빈 목록이면 아무도 신뢰하지 않는다(fail-safe: XFF 전면 무시).
 */
final class TrustedProxies {

    /** 네트워크 프리픽스 하나(v4=4바이트/v6=16바이트). 주소 패밀리가 다르면 불일치로 본다. */
    private record Cidr(byte[] network, int prefixLength) {
        boolean contains(InetAddress address) {
            byte[] candidate = address.getAddress();
            if (candidate.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (candidate[i] != network[i]) {
                    return false;
                }
            }
            int remainderBits = prefixLength % 8;
            if (remainderBits == 0) {
                return true;
            }
            int mask = (0xFF << (8 - remainderBits)) & 0xFF;
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }

    private final List<Cidr> ranges;

    private TrustedProxies(List<Cidr> ranges) {
        this.ranges = ranges;
    }

    /**
     * 설정 문자열 목록에서 판정기를 만든다. 항목은 IP 리터럴("127.0.0.1", "::1") 또는
     * CIDR("172.18.0.0/16")만 허용 — 잘못된 항목은 기동 시점에 예외로 실패시킨다(fail-fast,
     * 오타가 조용히 "아무도 신뢰 안 함"이 되어 스모크가 원인 불명으로 깨지는 것보다 낫다).
     */
    static TrustedProxies fromCidrs(List<String> entries) {
        List<Cidr> ranges = new ArrayList<>();
        for (String entry : entries) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int slash = trimmed.indexOf('/');
            String ipPart = slash >= 0 ? trimmed.substring(0, slash) : trimmed;
            // 호스트명 금지 — InetAddress.getByName이 DNS 조회로 엉뚱한 주소를 신뢰하게 되는 것을 막는다.
            if (!ipPart.contains(":") && !ipPart.matches("[0-9.]+")) {
                throw new IllegalArgumentException("trusted-proxies entry must be an IP literal or CIDR: " + entry);
            }
            byte[] network;
            try {
                network = InetAddress.getByName(ipPart).getAddress();
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("invalid trusted-proxies entry: " + entry, e);
            }
            int maxLength = network.length * 8;
            int prefixLength;
            try {
                prefixLength = slash >= 0 ? Integer.parseInt(trimmed.substring(slash + 1)) : maxLength;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid trusted-proxies prefix: " + entry, e);
            }
            if (prefixLength < 0 || prefixLength > maxLength) {
                throw new IllegalArgumentException("trusted-proxies prefix out of range (0.." + maxLength + "): " + entry);
            }
            ranges.add(new Cidr(network, prefixLength));
        }
        return new TrustedProxies(List.copyOf(ranges));
    }

    /** 이 원격주소가 신뢰 프록시인가 — 목록의 어느 한 프리픽스에라도 들면 참. */
    boolean isTrusted(InetAddress address) {
        for (Cidr range : ranges) {
            if (range.contains(address)) {
                return true;
            }
        }
        return false;
    }
}
