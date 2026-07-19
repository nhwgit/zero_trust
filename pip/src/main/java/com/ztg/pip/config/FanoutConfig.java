package com.ztg.pip.config;

import com.ztg.pip.fanout.EpochPublisher;
import com.ztg.pip.fanout.RedisEpochPublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * 능동 무효화 fan-out(발신측) 빈 구성. {@code ztg.fanout.enabled=true}면 Redis 발신점을, 아니면(기본)
 * no-op을 등록한다. no-op은 {@link StringRedisTemplate}를 주입받지 않으므로 Redis 서버 없이도 기동/테스트가 된다.
 */
@Configuration
class FanoutConfig {

    @Bean
    @ConditionalOnProperty(name = "ztg.fanout.enabled", havingValue = "true")
    EpochPublisher redisEpochPublisher(StringRedisTemplate redis) {
        return new RedisEpochPublisher(redis);
    }

    /** fan-out OFF(기본): lazy 학습+TTL 백스톱만으로 단일 노드 무효화가 성립한다. */
    @Bean
    @ConditionalOnMissingBean(EpochPublisher.class)
    EpochPublisher noopEpochPublisher() {
        return EpochPublisher.NOOP;
    }
}
