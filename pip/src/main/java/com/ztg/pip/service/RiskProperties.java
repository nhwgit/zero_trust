package com.ztg.pip.service;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * 위험 가중치·임계 설정({@code ztg.pip.risk.*}) 바인딩 — {@link RiskEngine}의 설정 입력.
 * {@code @Value} 9개 나열 대신 record로 묶어 생성자 비대를 막고, 테스트가 설정 묶음을 값으로 만든다.
 *
 * <p>같은 네임스페이스의 hold 설정({@code ip-change-hold}·{@code rate-l4-hold})은 점수 산출 입력이
 * 아니라 상태 유지 기간이므로 각 저장소가 따로 바인딩한다(여기 미포함 키는 바인더가 무시).
 */
@ConfigurationProperties("ztg.pip.risk")
public record RiskProperties(
        @DefaultValue("40") int deviceUntrustedWeight,
        @DefaultValue("30") int ipChangeWeight,
        @DefaultValue("40") int rateBurstWeight,
        @DefaultValue("40") int rateL4Weight,
        @DefaultValue("15") int offHoursWeight,
        @DefaultValue("60") int burstThreshold,
        @DefaultValue("40") int burstExitThreshold,
        @DefaultValue("9") int businessHourStart,
        @DefaultValue("18") int businessHourEnd) {
}
