package com.ztg.pip.fanout;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.ztg.common.fanout.EpochFanout;

/**
 * {@link EpochPublisher}의 Redis pub/sub 구현 — epoch 상승을 {@link EpochFanout#CHANNEL}로 publish한다.
 *
 * <p>fail-open: publish 실패는 로그만 남기고 삼킨다 — 백스톱(lazy 학습+TTL)이 있고, 위험 평가가
 * 캐시 전파 실패로 막히면 안 된다. publish는 assess 경로에서 동기이므로 Redis hang은
 * {@code spring.data.redis.timeout}(짧게, 기본 200ms)으로 바운드한다.
 */
public class RedisEpochPublisher implements EpochPublisher {

    private static final Logger log = LoggerFactory.getLogger(RedisEpochPublisher.class);

    private final StringRedisTemplate redis;

    public RedisEpochPublisher(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void publish(String subject, long epoch) {
        try {
            redis.convertAndSend(EpochFanout.CHANNEL, EpochFanout.encode(subject, epoch));
            log.info("epoch fan-out published subject={} epoch={}", subject, epoch);
        } catch (RuntimeException e) {
            log.warn("epoch fan-out publish failed subject={} epoch={}: {}", subject, epoch, e.toString());
        }
    }
}
