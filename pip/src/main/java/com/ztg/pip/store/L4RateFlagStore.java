package com.ztg.pip.store;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 커널(XDP) 에이전트가 보고한 L4 레이트 초과 소스 IP를 hold 동안 기억해 다음 평가에 반영한다.
 * hold가 지나면 자동 소멸(영구 차단이 아니라 가역적 위험적응). 만료는 조회 시 lazy로 걷어내고,
 * 시간은 단조 {@code nanoTime}(벽시계 점프 무관).
 */
@Component
public class L4RateFlagStore {

    /** 관측 근거(syns/window)를 함께 들어 위험 팩터 설명에 그대로 싣는다(설명 가능성). */
    public record Flag(String sourceIp, long synsInWindow, int windowSeconds, long expiresAtNanos) {}

    private final Map<String, Flag> flags = new ConcurrentHashMap<>();
    private final long holdNanos;
    private final LongSupplier nanoClock;

    @Autowired
    public L4RateFlagStore(@Value("${ztg.pip.risk.rate-l4-hold:30s}") Duration hold) {
        this(hold, System::nanoTime);
    }

    /** 테스트용 — 단조 시계를 주입해 hold 만료를 결정적으로 검증한다. */
    L4RateFlagStore(Duration hold, LongSupplier nanoClock) {
        this.holdNanos = hold.toNanos();
        this.nanoClock = nanoClock;
    }

    /** hold 길이(초) — 에지 차단(enforcement) TTL을 이 값과 동기화해 가역성 창을 하나로 유지한다. */
    public long holdSeconds() {
        return Duration.ofNanos(holdNanos).toSeconds();
    }

    /** 이 소스 IP를 hold 동안 플래그한다. 재보고는 만료를 연장하고 근거를 최신으로 덮는다. */
    public Flag flag(String sourceIp, long synsInWindow, int windowSeconds) {
        Flag f = new Flag(sourceIp, synsInWindow, windowSeconds, nanoClock.getAsLong() + holdNanos);
        flags.put(sourceIp, f);
        return f;
    }

    /** 유효한 플래그를 반환한다(없거나 만료·IP 미상이면 {@code null} = 무가중). 차이 비교로 nanoTime 래핑에 안전. */
    public Flag activeFlag(String sourceIp) {
        if (sourceIp == null || sourceIp.isBlank()) {
            return null;
        }
        Flag f = flags.get(sourceIp);
        if (f == null) {
            return null;
        }
        if (nanoClock.getAsLong() - f.expiresAtNanos() >= 0) {
            flags.remove(sourceIp, f);
            return null;
        }
        return f;
    }
}
