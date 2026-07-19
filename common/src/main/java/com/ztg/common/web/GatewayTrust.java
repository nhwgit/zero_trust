package com.ztg.common.web;

/**
 * 게이트웨이(PEP) 경유 증명에 쓰는 내부 신뢰 헤더의 공용 상수.
 * 주입(게이트웨이)·검증(resource-api)이 같은 헤더명을 써야 하는 와이어 규약이라 정본을 common에 둔다.
 */
public final class GatewayTrust {

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. 게이트웨이가 주입하고 resource-api가 검증한다. */
    public static final String HEADER = "X-Gateway-Auth";

    private GatewayTrust() {
    }
}
