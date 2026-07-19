package com.ztg.pip.fanout;

/**
 * 주체의 위험 epoch가 올랐을 때 그 사실을 게이트웨이들에 알리는 발신점.
 * fan-out은 가속기일 뿐 — 끄더라도 게이트웨이의 lazy 학습+TTL이 무효화를 보장한다(백스톱).
 */
public interface EpochPublisher {

    /** 끈 상태(단일 노드/테스트)에서 쓰는 무동작 발신점. */
    EpochPublisher NOOP = (subject, epoch) -> {
    };

    /** 이 주체의 epoch가 {@code epoch}까지 올랐음을 전파한다. 실패는 삼킨다(백스톱이 있으므로 fail-open). */
    void publish(String subject, long epoch);
}
