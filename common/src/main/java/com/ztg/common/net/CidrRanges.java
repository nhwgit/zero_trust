package com.ztg.common.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * IP/CIDR 목록 매칭 — "이 주소가 알려진 대역에 드는가"의 공유 판정기.
 * 게이트웨이의 신뢰 프록시(XFF 인정)와 PIP의 에지 차단 제외가 같은 구현을 쓴다.
 * 빈 목록이면 아무것도 매칭하지 않는다(fail-safe).
 */
public final class CidrRanges {

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

    private CidrRanges(List<Cidr> ranges) {
        this.ranges = ranges;
    }

    /**
     * IP 리터럴 또는 CIDR 목록에서 판정기를 만든다. 잘못된 항목은 기동 시점에 예외로 실패시킨다
     * (fail-fast: 오타가 조용히 "아무도 매칭 안 됨"이 되는 것 방지). {@code settingName}은 어느 설정이
     * 틀렸는지 메시지에 싣기 위한 라벨이다.
     */
    public static CidrRanges parse(List<String> entries, String settingName) {
        List<Cidr> ranges = new ArrayList<>();
        for (String entry : entries) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int slash = trimmed.indexOf('/');
            String ipPart = slash >= 0 ? trimmed.substring(0, slash) : trimmed;
            // 호스트명 금지 — InetAddress.getByName이 DNS 조회로 엉뚱한 주소를 매칭하게 되는 것을 막는다.
            if (!isIpLiteral(ipPart)) {
                throw new IllegalArgumentException(settingName + " entry must be an IP literal or CIDR: " + entry);
            }
            byte[] network;
            try {
                network = InetAddress.getByName(ipPart).getAddress();
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("invalid " + settingName + " entry: " + entry, e);
            }
            int maxLength = network.length * 8;
            int prefixLength;
            try {
                prefixLength = slash >= 0 ? Integer.parseInt(trimmed.substring(slash + 1)) : maxLength;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid " + settingName + " prefix: " + entry, e);
            }
            if (prefixLength < 0 || prefixLength > maxLength) {
                throw new IllegalArgumentException(
                        settingName + " prefix out of range (0.." + maxLength + "): " + entry);
            }
            ranges.add(new Cidr(network, prefixLength));
        }
        return new CidrRanges(List.copyOf(ranges));
    }

    public boolean contains(InetAddress address) {
        for (Cidr range : ranges) {
            if (range.contains(address)) {
                return true;
            }
        }
        return false;
    }

    /** IP 리터럴 문자열 판정 — 리터럴이 아니면(호스트명 등) DNS 조회 없이 불일치로 본다. */
    public boolean containsLiteral(String ip) {
        if (ip == null || ip.isBlank() || !isIpLiteral(ip.trim())) {
            return false;
        }
        try {
            return contains(InetAddress.getByName(ip.trim()));
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean isIpLiteral(String ipPart) {
        return ipPart.contains(":") || ipPart.matches("[0-9.]+");
    }
}
