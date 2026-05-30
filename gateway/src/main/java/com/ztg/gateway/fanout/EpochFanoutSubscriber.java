package com.ztg.gateway.fanout;

import com.ztg.gateway.cache.DecisionCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;

import com.ztg.common.fanout.EpochFanout;

import java.nio.charset.StandardCharsets;

/**
 * 다른 게이트웨이가 유발한 epoch 상승을 Redis 채널에서 받아 이 노드의 {@link DecisionCache}에 적용한다.
 *
 * <p>한 노드에서 위험이 올라 PIP가 epoch를 bump하면 PIP가 {@link EpochFanout#CHANNEL}로 publish하고,
 * 이 구독자가 모든 노드에서 그 메시지를 받아 {@link DecisionCache#applyRemoteEpoch}를 호출한다 →
 * 위험을 유발하지 않은 노드도 자기 PDP 왕복을 기다리지 않고 그 주체의 캐시를 즉시 키-아웃한다.
 *
 * <p>한 건의 파싱 실패가 구독을 끊지 않도록 {@link EpochFanout#decode} 예외는 잡아 그 메시지만 버린다.
 */
public class EpochFanoutSubscriber implements MessageListener {

    private static final Logger log = LoggerFactory.getLogger(EpochFanoutSubscriber.class);

    private final DecisionCache decisionCache;

    public EpochFanoutSubscriber(DecisionCache decisionCache) {
        this.decisionCache = decisionCache;
    }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        String payload = new String(message.getBody(), StandardCharsets.UTF_8);
        try {
            EpochFanout.Message decoded = EpochFanout.decode(payload);
            decisionCache.applyRemoteEpoch(decoded.subject(), decoded.epoch());
            log.debug("epoch fan-out applied subject={} epoch={}", decoded.subject(), decoded.epoch());
        } catch (IllegalArgumentException e) {
            // 깨진 한 건은 버리고 구독은 계속한다(다른 노드/버전이 보낸 잡음에 견고).
            log.warn("ignoring malformed epoch fan-out payload: {}", e.getMessage());
        }
    }
}
