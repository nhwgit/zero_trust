package com.ztg.pip;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.ztg.common.EpochFanout;

/**
 * {@link EpochPublisher}의 Redis pub/sub 구현 — epoch 상승을 {@link EpochFanout#CHANNEL} 채널로 publish해
 * 모든 게이트웨이가 동시에 캐시를 키-아웃하게 한다. {@code ztg.fanout.enabled=true}일 때만 빈으로 등록된다.
 *
 * <p><b>fail-open:</b> Redis가 잠깐 끊겨 publish가 실패해도 예외를 흘리지 않는다 — fan-out은 무효화를
 * 앞당기는 가속기일 뿐이고, 게이트웨이별 lazy 학습+TTL이 백스톱이다([[EpochFanout]]). 위험 평가 자체가
 * 캐시 전파 실패로 막히면 안 되므로(가용성), 로그만 남기고 진행한다.
 *
 * <p>이 publish는 평가(assess) 경로에서 <b>동기</b>로 일어나므로, Redis가 예외 없이 <b>행(hang)</b>하면
 * 예외를 못 잡고 평가가 블록될 수 있다. 그래서 {@code spring.data.redis.timeout}을 짧게(기본 200ms) 잡아
 * 최악의 블록을 bump 경로 한정 200ms로 바운드한다 — 타임아웃은 여기서 예외로 떨어져 아래 catch가 삼킨다.
 * (bump 자체가 드물어 — 점수 전이 때만 — 정상 경로엔 영향이 없다.)
 */
class RedisEpochPublisher implements EpochPublisher {

    private static final Logger log = LoggerFactory.getLogger(RedisEpochPublisher.class);

    private final StringRedisTemplate redis;

    RedisEpochPublisher(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void publish(String subject, long epoch) {
        try {
            redis.convertAndSend(EpochFanout.CHANNEL, EpochFanout.encode(subject, epoch));
            log.info("epoch fan-out published subject={} epoch={}", subject, epoch);
        } catch (RuntimeException e) {
            // 백스톱(lazy 학습+TTL)이 있으므로 전파 실패는 거부가 아니다. 가용성 우선: 삼키고 진행.
            log.warn("epoch fan-out publish failed subject={} epoch={}: {}", subject, epoch, e.toString());
        }
    }
}
