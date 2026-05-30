package com.ztg.gateway.config;

import com.ztg.gateway.cache.DecisionCache;
import com.ztg.gateway.fanout.EpochFanoutSubscriber;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import com.ztg.common.fanout.EpochFanout;

/**
 * 능동 무효화 fan-out(수신측) 빈 구성. {@code ztg.fanout.enabled=true}일 때만 Redis 구독 컨테이너를 띄운다.
 *
 * <p>기본(플래그 OFF)에서는 이 구성 전체가 비활성이라 게이트웨이는 Redis에 연결하지 않는다 — 단일 GW와
 * 단위테스트는 Redis 없이 그대로 동작하고(lazy 학습+TTL만으로 무효화 성립), 다중 GW 데모에서만 켠다.
 *
 * <p>구독 처리는 컨테이너의 별도 스레드에서 일어나므로 게이트웨이의 리액티브 이벤트 루프(요청 핫패스)를
 * 막지 않는다 — fan-out 적용은 캐시 상태 갱신일 뿐 요청 경로 위가 아니다.
 */
@Configuration
@ConditionalOnProperty(name = "ztg.fanout.enabled", havingValue = "true")
class FanoutConfig {

    /** epoch 상승을 받아 이 노드의 캐시에 적용하는 구독자. */
    @Bean
    EpochFanoutSubscriber epochFanoutSubscriber(DecisionCache decisionCache) {
        return new EpochFanoutSubscriber(decisionCache);
    }

    /** {@link EpochFanout#CHANNEL} 채널을 구독해 메시지를 구독자에게 전달하는 컨테이너. */
    @Bean
    RedisMessageListenerContainer epochListenerContainer(RedisConnectionFactory connectionFactory,
                                                         EpochFanoutSubscriber subscriber) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.addMessageListener(subscriber, new ChannelTopic(EpochFanout.CHANNEL));
        return container;
    }
}
