package com.ztg.gateway.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import com.ztg.gateway.config.RateProperties;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

/**
 * {@link RedisRateObserver} 단위 테스트 — 공유 카운트 채택 / 장애 시 로컬 폴백(fail-degraded) /
 * warm standby(폴백이 빈 윈도우에서 시작하지 않음)를 Redis 템플릿 목으로 검증한다.
 */
class RedisRateObserverTest {

    private final RateProperties rate = new RateProperties(Duration.ofSeconds(10), 60, 40);
    private final SubjectRateObserver local = new SubjectRateObserver(rate);
    private ReactiveStringRedisTemplate redis;
    private RedisRateObserver observer;

    @BeforeEach
    void setUp() {
        redis = mock(ReactiveStringRedisTemplate.class);
        observer = new RedisRateObserver(redis, local, rate, new SimpleMeterRegistry());
    }

    @Test
    @SuppressWarnings("unchecked")
    void usesSharedCountAndSubjectScopedKey() {
        doReturn(Flux.just(7L)).when(redis).execute(any(RedisScript.class), anyList(), anyList());

        StepVerifier.create(observer.observe("alice")).expectNext(7).verifyComplete();

        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        verify(redis).execute(any(RedisScript.class), keys.capture(), anyList());
        assertThat(keys.getValue()).containsExactly(RedisRateObserver.KEY_PREFIX + "alice");
    }

    @Test
    @SuppressWarnings("unchecked")
    void fallsBackToLocalCountOnRedisFailure() {
        doReturn(Flux.error(new IllegalStateException("redis down")))
                .when(redis).execute(any(RedisScript.class), anyList(), anyList());

        // 폴백은 로컬 카운터의 값 — 요청은 정확히 한 번만 세어진다(1, 2로 단조 증가 = 이중 계상 없음).
        StepVerifier.create(observer.observe("alice")).expectNext(1).verifyComplete();
        StepVerifier.create(observer.observe("alice")).expectNext(2).verifyComplete();
    }

    @Test
    @SuppressWarnings("unchecked")
    void warmStandbyKeepsLocalWindowDuringSharedOperation() {
        // 공유 집계가 살아 있는 동안에도 로컬 카운터를 함께 적신다 —
        doReturn(Flux.just(50L)).when(redis).execute(any(RedisScript.class), anyList(), anyList());
        StepVerifier.create(observer.observe("alice")).expectNext(50).verifyComplete();
        StepVerifier.create(observer.observe("alice")).expectNext(50).verifyComplete();

        // — 그래서 장애로 강등되는 순간 폴백이 빈 윈도우(1)가 아니라 이어지는 값(3)에서 시작한다.
        doReturn(Flux.error(new IllegalStateException("redis down")))
                .when(redis).execute(any(RedisScript.class), anyList(), anyList());
        StepVerifier.create(observer.observe("alice")).expectNext(3).verifyComplete();
    }
}
