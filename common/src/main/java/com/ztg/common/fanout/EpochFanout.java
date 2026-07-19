package com.ztg.common.fanout;

/**
 * 다중 게이트웨이 능동 무효화 fan-out의 와이어 규약 — Redis pub/sub 채널명 + 메시지 코덱.
 *
 * <p>pub/sub은 at-most-once지만, 게이트웨이별 lazy 학습 + 위험적응 TTL이 백스톱이라 유실이 안전하다
 * (fan-out은 무효화를 앞당기는 가속기일 뿐 유일한 경로가 아니다).
 * 코덱은 {@code "<epoch>\t<subject>"} — epoch를 앞에 둬 subject에 공백이 있어도 안전하다.
 */
public final class EpochFanout {

    /** 능동 무효화 fan-out 채널. publisher(PIP)·subscriber(모든 GW)가 같은 이름을 써야 한다. */
    public static final String CHANNEL = "ztg:epoch";

    private static final char SEP = '\t';

    private EpochFanout() {
    }

    public record Message(String subject, long epoch) {
    }

    public static String encode(String subject, long epoch) {
        return epoch + Character.toString(SEP) + subject;
    }

    /** 형식이 깨졌으면 {@link IllegalArgumentException} — 구독자는 이를 잡아 한 건만 버리고 계속 받는다. */
    public static Message decode(String payload) {
        if (payload == null) {
            throw new IllegalArgumentException("epoch fan-out payload is null");
        }
        int sep = payload.indexOf(SEP);
        if (sep < 0) {
            throw new IllegalArgumentException("epoch fan-out payload missing separator: " + payload);
        }
        long epoch;
        try {
            epoch = Long.parseLong(payload.substring(0, sep));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("epoch fan-out payload has non-numeric epoch: " + payload, e);
        }
        return new Message(payload.substring(sep + 1), epoch);
    }
}
