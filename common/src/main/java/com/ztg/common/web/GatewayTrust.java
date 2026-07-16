package com.ztg.common.web;

/**
 * 게이트웨이(PEP) 경유 증명에 쓰는 내부 신뢰 헤더의 공용 상수.
 *
 * <p>게이트웨이(주입)와 resource-api(검증)가 같은 헤더명을 써야 성립하는 <b>와이어 규약</b>이다 —
 * 두 모듈이 각자 상수를 들고 있으면 한쪽만 바뀌는 순간 모든 요청이 403으로 무너진다.
 * {@link RequestId}와 같은 이유로 규약의 정본을 common 한 곳에 둔다(비밀 <b>값</b>의 정합은 설정 몫).
 */
public final class GatewayTrust {

    /** 게이트웨이 경유를 증명하는 내부 신뢰 헤더. 게이트웨이가 주입하고 resource-api가 검증한다. */
    public static final String HEADER = "X-Gateway-Auth";

    private GatewayTrust() {
    }
}
