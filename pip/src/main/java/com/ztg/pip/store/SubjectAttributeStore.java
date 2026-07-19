package com.ztg.pip.store;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.ztg.common.model.SubjectAttributes;

/**
 * 주체 속성의 in-memory 저장소(데모용 단순화). fail-safe: 모르는 주체는 가장 보수적인 프로필
 * (비신뢰·위험점수 100)을 돌려줘 "정보 없음 = 최대 위험"으로 다룬다.
 */
@Component
public class SubjectAttributeStore {

    private final Map<String, SubjectAttributes> store = new ConcurrentHashMap<>();

    public SubjectAttributeStore() {
        // 데모 시드: alice는 payroll 정상 케이스, bob은 부서 조건에서 막히는 케이스.
        store.put("alice", new SubjectAttributes("alice", "finance", true, 10));
        store.put("bob", new SubjectAttributes("bob", "engineering", true, 20));
    }

    /** 미등록 주체는 보수적 기본값(최대 위험)을 반환한다. */
    public SubjectAttributes get(String subject) {
        return store.getOrDefault(subject,
                new SubjectAttributes(subject, "unknown", false, 100));
    }

    /** 데모용: 속성을 통째로 덮어써 정책 결과를 뒤집어 볼 수 있게 한다. */
    public SubjectAttributes put(SubjectAttributes attributes) {
        store.put(attributes.subject(), attributes);
        return attributes;
    }
}
