package com.ztg.pip.web;

import com.ztg.pip.store.SubjectAttributeStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ztg.common.model.SubjectAttributes;

/**
 * 주체 속성 조회(GET, 미등록이면 보수적 기본값)·데모용 변경(PUT) 표면.
 */
@RestController
@RequestMapping("/pip/attributes")
public class PipController {

    private final SubjectAttributeStore store;

    public PipController(SubjectAttributeStore store) {
        this.store = store;
    }

    @GetMapping("/{subject}")
    public SubjectAttributes get(@PathVariable String subject) {
        return store.get(subject);
    }

    /** body의 subject는 무시하고 경로의 subject로 저장한다(경로가 권위). */
    @PutMapping("/{subject}")
    public SubjectAttributes put(@PathVariable String subject, @RequestBody UpdateRequest body) {
        return store.put(new SubjectAttributes(
                subject, body.department(), body.deviceTrusted(), body.riskScore()));
    }

    public record UpdateRequest(String department, boolean deviceTrusted, int riskScore) {
    }
}
