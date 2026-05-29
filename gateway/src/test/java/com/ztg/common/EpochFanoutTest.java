package com.ztg.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * {@link EpochFanout} 와이어 코덱 L2 — publisher(PIP)·subscriber(GW)가 같은 규약으로 인코딩/디코딩하는지,
 * 깨진 페이로드를 명확한 예외로 거르는지 검증한다(구독자가 한 건 실패에 구독을 끊지 않도록).
 */
class EpochFanoutTest {

    @Test
    void roundTripsSubjectAndEpoch() {
        String payload = EpochFanout.encode("alice", 7L);
        EpochFanout.Message decoded = EpochFanout.decode(payload);
        assertThat(decoded.subject()).isEqualTo("alice");
        assertThat(decoded.epoch()).isEqualTo(7L);
    }

    @Test
    void preservesSubjectsContainingSpaces() {
        // epoch를 앞에 두고 첫 구분자까지만 epoch로 파싱하므로 subject에 공백이 있어도 온전히 복원된다.
        EpochFanout.Message decoded = EpochFanout.decode(EpochFanout.encode("svc account 1", 3L));
        assertThat(decoded.subject()).isEqualTo("svc account 1");
        assertThat(decoded.epoch()).isEqualTo(3L);
    }

    @Test
    void rejectsMalformedPayloads() {
        assertThatThrownBy(() -> EpochFanout.decode("no-separator"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EpochFanout.decode("notanumber\talice"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EpochFanout.decode(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
