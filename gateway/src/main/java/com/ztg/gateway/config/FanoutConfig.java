package com.ztg.gateway.config;

import com.ztg.gateway.cache.DecisionCache;
import com.ztg.gateway.fanout.EpochFanoutSubscriber;
import com.ztg.gateway.risk.RateObserver;
import com.ztg.gateway.risk.RedisRateObserver;
import com.ztg.gateway.risk.SubjectRateObserver;

import io.micrometer.core.instrument.MeterRegistry;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import com.ztg.common.fanout.EpochFanout;

/**
 * 다중 GW 모드({@code ztg.fanout.enabled=true}) 전용 빈 구성 — 능동 무효화 fan-out(수신측) +
 * 레이트 관측 소유권 승격(Redis 공유 집계). 플래그 OFF(기본)면 이 구성 전체가 비활성이라
 * 게이트웨이는 Redis에 연결하지 않는다.
 */
@Configuration
@ConditionalOnProperty(name = "ztg.fanout.enabled", havingValue = "true")
class FanoutConfig {

    /** 레이트 관측을 Redis 공유 집계로 승격하되, 로컬 카운터를 폴백으로 물려준다(fail-degraded). */
    @Bean
    @Primary
    RateObserver sharedRateObserver(ReactiveStringRedisTemplate redisTemplate,
                                    SubjectRateObserver localObserver,
                                    RateProperties rate,
                                    MeterRegistry meterRegistry) {
        return new RedisRateObserver(redisTemplate, localObserver, rate, meterRegistry);
    }

    @Bean
    EpochFanoutSubscriber epochFanoutSubscriber(DecisionCache decisionCache) {
        return new EpochFanoutSubscriber(decisionCache);
    }

    @Bean
    RedisMessageListenerContainer epochListenerContainer(RedisConnectionFactory connectionFactory,
                                                         EpochFanoutSubscriber subscriber) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.addMessageListener(subscriber, new ChannelTopic(EpochFanout.CHANNEL));
        return container;
    }
}
