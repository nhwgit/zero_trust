package com.ztg.pip;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * 주체별 <b>지속(stateful)</b> 위험 맥락 — 현재는 직전 관측 IP만 보관한다.
 *
 * <p>IP 변화 신호는 "지금 IP가 직전과 다른가"라 직전 값을 기억해야 한다(휘발성 신호와 달리 상태가 필요).
 * 슬라이딩 윈도우 레이트는 모든 요청을 보는 게이트웨이가 관측하므로(README 결정 #3) 여기 두지 않는다.
 *
 * <p>설계 메모: 데모에서 ALLOW→DENY를 시연한 뒤 원상복구할 수 있도록 {@link #evict}로 주체 상태를
 * 비울 수 있게 둔다. in-memory(단일 PIP) — 다중화는 D1 확장(Redis)으로 미룬다.
 */
@Component
public class SubjectRiskState {

    private final Map<String, String> lastSeenIp = new ConcurrentHashMap<>();

    /** 직전 관측 IP를 반환한다(없으면 {@code null} = 첫 관측 → IP 변화로 치지 않음). */
    public String lastSeenIp(String subject) {
        return lastSeenIp.get(subject);
    }

    /** 이번 관측 IP를 기록한다(다음 요청의 IP 변화 비교 기준). null/blank는 무시(미상 IP는 기준을 덮지 않음). */
    public void recordIp(String subject, String sourceIp) {
        if (sourceIp != null && !sourceIp.isBlank()) {
            lastSeenIp.put(subject, sourceIp);
        }
    }

    /** 데모 리셋: 주체의 위험 상태를 비운다(다음 관측은 첫 관측으로 취급). */
    public void evict(String subject) {
        lastSeenIp.remove(subject);
    }
}
