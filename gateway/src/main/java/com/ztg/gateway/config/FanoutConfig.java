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
 * 레이트 관측 소유권 승격(Redis 공유 집계).
 *
 * <p>기본(플래그 OFF)에서는 이 구성 전체가 비활성이라 게이트웨이는 Redis에 연결하지 않는다 — 단일 GW와
 * 단위테스트는 Redis 없이 그대로 동작하고(lazy 학습+TTL만으로 무효화 성립, 레이트는 노드-로컬),
 * 다중 GW 데모에서만 켠다.
 *
 * <p><b>플래그를 공유하는 이유:</b> "GW가 여러 대"라는 같은 사실이 fan-out(무효화 전파)과 공유 레이트
 * 집계(희석 방지)를 <b>둘 다</b> 요구한다 — 한쪽만 켜면 각각의 다중 GW 결함이 되살아나므로 별도 노브를
 * 두지 않고, 이미 fan-out에 필수인 같은 Redis를 재사용한다(관리포인트 불증).
 *
 * <p>구독 처리는 컨테이너의 별도 스레드에서 일어나므로 게이트웨이의 리액티브 이벤트 루프(요청 핫패스)를
 * 막지 않는다 — fan-out 적용은 캐시 상태 갱신일 뿐 요청 경로 위가 아니다. 레이트 집계는 요청 경로
 * 위지만 비차단 리액티브 호출이다({@link RedisRateObserver} 비용·강등 정책 참조).
 */
@Configuration
@ConditionalOnProperty(name = "ztg.fanout.enabled", havingValue = "true")
class FanoutConfig {

    /**
     * 레이트 관측 소유권을 노드-로컬 카운터에서 Redis 공유 집계로 승격한다. {@code @Primary}로
     * 로컬 {@link SubjectRateObserver}를 대체하되, 그 로컬 카운터를 폴백으로 물려준다(fail-degraded).
     */
    @Bean
    @Primary
    RateObserver sharedRateObserver(ReactiveStringRedisTemplate redisTemplate,
                                    SubjectRateObserver localObserver,
                                    RateProperties rate,
                                    MeterRegistry meterRegistry) {
        return new RedisRateObserver(redisTemplate, localObserver, rate, meterRegistry);
    }

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
