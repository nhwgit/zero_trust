package com.ztg.pip;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.ztg.common.SubjectAttributes;

/**
 * 주체 속성의 in-memory 저장소. 초기엔 메모리, 후반(roadmap)에는 Redis/PostgreSQL로 교체.
 *
 * <p>데모 시드: realm의 사용자(alice/bob)에 부서·디바이스신뢰·위험점수를 부여한다.
 * 데모에서 정책 조건을 바꿔보기 위해 {@link #put}으로 런타임에 속성을 변경할 수 있다.
 *
 * <p>설계 메모(fail-safe): 모르는 주체는 <b>가장 보수적인 프로필</b>(부서 unknown,
 * 디바이스 비신뢰, 위험점수 100)을 돌려준다. "정보 없음 = 최대 위험"으로 다뤄 PDP가
 * 안전하게(차단 쪽으로) 판단하도록 한다.
 */
@Component
public class SubjectAttributeStore {

    private final Map<String, SubjectAttributes> store = new ConcurrentHashMap<>();

    public SubjectAttributeStore() {
        // alice: finance 부서, 신뢰 디바이스, 저위험 → payroll 정책의 정상 케이스
        store.put("alice", new SubjectAttributes("alice", "finance", true, 10));
        // bob: engineering 부서, 신뢰 디바이스, 저위험 → 부서 조건에서 막히는 케이스
        store.put("bob", new SubjectAttributes("bob", "engineering", true, 20));
    }

    /** 주체 속성을 조회한다. 미등록 주체는 보수적 기본값(최대 위험)을 반환한다. */
    public SubjectAttributes get(String subject) {
        return store.getOrDefault(subject,
                new SubjectAttributes(subject, "unknown", false, 100));
    }

    /** 데모용: 주체 속성을 통째로 덮어쓴다(부서/디바이스/위험점수 변경으로 정책 결과를 뒤집어 보기 위함). */
    public SubjectAttributes put(SubjectAttributes attributes) {
        store.put(attributes.subject(), attributes);
        return attributes;
    }
}
