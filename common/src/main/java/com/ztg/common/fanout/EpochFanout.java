package com.ztg.common.fanout;

/**
 * 다중 게이트웨이 <b>능동 무효화 fan-out</b>의 와이어 규약 — 채널명 + 메시지 코덱.
 *
 * <p>단일 게이트웨이에서 능동 무효화는 PDP 왕복에 piggyback된 {@code epoch}를 게이트웨이가
 * <b>lazy 학습</b>해 동작한다(자기 트래픽이 PDP를 한 번 다녀와야 새 epoch를 안다). 게이트웨이가
 * 여러 대면, <b>위험 상승을 유발하지 않은</b> 다른 게이트웨이는 그 주체의 PDP 왕복이 일어날 때까지
 * 옛 ALLOW를 TTL 동안 계속 캐시 히트로 내준다 — 노드 간 무효화 지연.
 *
 * <p>그래서 epoch 권위자(PIP)가 epoch를 올리는 <b>그 순간</b> {@code (subject, epoch)}를 Redis
 * pub/sub 채널로 publish하고, <b>모든</b> 게이트웨이가 구독해 자기 {@code knownEpochs}를 즉시 끌어올린다 →
 * 한 노드에서 오른 epoch가 전 노드의 캐시를 <b>동시에</b> 키-아웃한다(재로그인 없는 ALLOW→DENY를 다중 GW로 확장).
 *
 * <p><b>전달 보장:</b> Redis pub/sub은 at-most-once(구독자 부재/순간 단절 시 유실 가능)다. 그래도
 * 안전한 이유는 게이트웨이별 <b>lazy 학습 + 위험적응 TTL</b>이 <b>백스톱</b>이기 때문이다 — fan-out은
 * 무효화를 <b>앞당기는 가속기</b>일 뿐, 유일한 경로가 아니다. 그래서 Kafka 같은 지속/재생이 필요 없다.
 *
 * <p>코덱: {@code "<epoch>\t<subject>"}. epoch를 앞에 둬 첫 탭까지를 epoch로 파싱하고 나머지를 그대로
 * subject로 취한다 — subject(사용자명)에 공백 등이 있어도 안전하다(탭은 사용자명에 사실상 없음).
 */
public final class EpochFanout {

    /** 능동 무효화 fan-out 채널. publisher(PIP)·subscriber(모든 GW)가 같은 이름을 써야 한다. */
    public static final String CHANNEL = "ztg:epoch";

    private static final char SEP = '\t';

    private EpochFanout() {
    }

    /** fan-out 메시지: 어느 주체의 epoch가 어디까지 올랐는가. */
    public record Message(String subject, long epoch) {
    }

    /** {@code (subject, epoch)} → 와이어 페이로드. */
    public static String encode(String subject, long epoch) {
        return epoch + Character.toString(SEP) + subject;
    }

    /**
     * 와이어 페이로드 → {@link Message}. 형식이 깨졌으면(구분자 없음/숫자 아님) {@link IllegalArgumentException}.
     * 호출부(구독자)는 이를 잡아 한 메시지를 버리고 다음을 계속 받는다 — 한 건 파싱 실패가 구독을 끊지 않게.
     */
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
