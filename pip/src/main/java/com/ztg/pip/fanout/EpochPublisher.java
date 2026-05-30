package com.ztg.pip;

/**
 * 주체의 위험 epoch가 올랐을 때 그 사실을 게이트웨이들에 알리는 발신점.
 *
 * <p>PIP는 epoch의 <b>권위자</b>다(점수 변화 시 {@link SubjectRiskState}가 +1). 다중 게이트웨이에서
 * 그 상승을 모든 노드에 <b>즉시</b> 전파하려면 PIP가 변화 순간 publish해야 한다 — 그래야 위험을
 * 유발하지 않은 게이트웨이도 자기 PDP 왕복을 기다리지 않고 캐시를 키-아웃한다([[EpochFanout]] 참고).
 *
 * <p>구현은 두 가지: {@code ztg.fanout.enabled=true}면 Redis로 publish, 아니면 no-op(단일 PIP/테스트).
 * fan-out은 가속기일 뿐이라 끄더라도 게이트웨이의 lazy 학습+TTL이 무효화를 보장한다(백스톱).
 */
public interface EpochPublisher {

    /** 끈 상태(단일 노드/테스트)에서 쓰는 무동작 발신점. */
    EpochPublisher NOOP = (subject, epoch) -> {
    };

    /** 이 주체의 epoch가 {@code epoch}까지 올랐음을 전파한다. 실패는 삼킨다(백스톱이 있으므로 fail-open). */
    void publish(String subject, long epoch);
}
