package com.ztg.gateway.risk;

import reactor.core.publisher.Mono;

/**
 * 주체별 요청 레이트 관측의 추상화 — "이번 요청을 세고, 윈도우 안 요청 수(이번 것 포함)를 돌려준다".
 *
 * <p>구현이 곧 <b>관측 소유권</b>이다. 단일 GW(기본)는 노드-로컬 인메모리({@link SubjectRateObserver})로
 * 충분하지만, GW가 N대면 같은 주체의 폭주가 노드마다 1/N로 희석돼 어느 노드도 임계를 못 넘는다(전역
 * 폭주 미검출). 또 노드마다 다른 로컬 카운트가 PIP의 주체당 밴드 상태에 섞여 들어가 비대칭 라우팅 시
 * 밴드가 플립-플롭한다(epoch bump 폭풍 → fan-out이 전 노드 캐시를 계속 키-아웃하는 증폭기 역전).
 * 그래서 다중 GW 모드에선 공유 집계({@link RedisRateObserver})가 이 자리를 대체한다 — 모든 노드가
 * 같은 전역 카운트를 보므로 두 증상이 근원에서 사라진다.
 *
 * <p>반환이 {@link Mono}인 이유: 공유 집계는 네트워크 I/O라 게이트웨이의 리액티브 이벤트 루프를
 * 막지 않는 체인이어야 한다. 로컬 구현은 즉시 완료되는 Mono로 감싼다.
 */
public interface RateObserver {

    /** 이 주체의 이번 요청을 기록하고, 윈도우 안에 남은 요청 수(이번 것 포함)를 돌려준다. */
    Mono<Integer> observe(String subject);
}
