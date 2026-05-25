package com.ztg.common;

/** PDP의 판단 결과. 제로트러스트 기본값은 DENY(판단 불가/오류 시 차단). */
public enum Decision {
    ALLOW,
    DENY
}
