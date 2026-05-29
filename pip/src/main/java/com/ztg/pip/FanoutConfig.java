package com.ztg.pip;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 능동 무효화 fan-out(발신측) 빈 구성. {@code ztg.fanout.enabled=true}면 Redis 발신점을, 아니면(기본)
 * no-op을 등록한다 — 단일 PIP/단위테스트는 Redis 없이 동작하고, 다중 게이트웨이 데모에서만 켠다.
 *
 * <p>플래그가 꺼져 있으면 Spring Boot가 Redis 연결을 자동구성하더라도 {@link StringRedisTemplate}를
 * <b>주입받지 않는</b> no-op만 활성화되므로 Redis 서버가 없어도 기동/테스트가 깨지지 않는다.
 */
@Configuration
class FanoutConfig {

    /** fan-out ON: epoch 상승을 Redis 채널로 publish. */
    @Bean
    @ConditionalOnProperty(name = "ztg.fanout.enabled", havingValue = "true")
    EpochPublisher redisEpochPublisher(StringRedisTemplate redis) {
        return new RedisEpochPublisher(redis);
    }

    /** fan-out OFF(기본): 무동작. lazy 학습+TTL 백스톱만으로 단일 노드 무효화가 성립한다. */
    @Bean
    @ConditionalOnMissingBean(EpochPublisher.class)
    EpochPublisher noopEpochPublisher() {
        return EpochPublisher.NOOP;
    }
}
