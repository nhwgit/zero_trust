package com.ztg.pip;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.ztg.common.SubjectAttributes;

/** 속성 저장소 검증 — 시드/변경/미등록 기본값(보수적) 동작. */
class SubjectAttributeStoreTest {

    private final SubjectAttributeStore store = new SubjectAttributeStore();

    @Test
    void seeds_known_users() {
        SubjectAttributes alice = store.get("alice");
        assertThat(alice.department()).isEqualTo("finance");
        assertThat(alice.deviceTrusted()).isTrue();
    }

    @Test
    void unknown_subject_gets_conservative_default() {
        SubjectAttributes unknown = store.get("mallory");
        assertThat(unknown.department()).isEqualTo("unknown");
        assertThat(unknown.deviceTrusted()).isFalse();
        assertThat(unknown.riskScore()).isEqualTo(100);   // 최대 위험 = fail-safe
    }

    @Test
    void put_overwrites_attributes() {
        store.put(new SubjectAttributes("alice", "engineering", false, 50));

        SubjectAttributes alice = store.get("alice");
        assertThat(alice.department()).isEqualTo("engineering");
        assertThat(alice.deviceTrusted()).isFalse();
        assertThat(alice.riskScore()).isEqualTo(50);
    }
}
