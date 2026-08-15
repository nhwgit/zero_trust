package com.ztg.common.model;

/** PDP의 판단 결과. 제로트러스트 기본값은 차단 — 판단 불가도 통과시키지 않는다. */
public enum Decision {
    ALLOW,
    DENY,
    /** 맥락 부재로 판단 불성립(XACML Indeterminate). 집행은 DENY와 같으나 PEP가 캐시하지 않는다. */
    INDETERMINATE
}
