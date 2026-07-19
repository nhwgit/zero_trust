package com.ztg.gateway.risk;

import reactor.core.publisher.Mono;

/**
 * 주체별 요청 레이트 관측의 추상화. 단일 GW(기본)는 노드-로컬({@link SubjectRateObserver}),
 * 다중 GW는 폭주의 1/N 희석을 막기 위해 공유 집계({@link RedisRateObserver})가 소유한다.
 * 반환이 {@link Mono}인 이유: 공유 집계는 네트워크 I/O라 이벤트 루프를 막지 않는 체인이어야 한다.
 */
public interface RateObserver {

    /** 이 주체의 이번 요청을 기록하고, 윈도우 안에 남은 요청 수(이번 것 포함)를 돌려준다. */
    Mono<Integer> observe(String subject);
}
