# L4 트러블슈팅을 "와이어에서" — tc netem 장애주입·진단 실습 기록

> 실습1(mTLS 핸드셰이크 입증)에 이어, **정책 경로(pdp↔pip)에 L4 장애를 인위 주입**하고 그 증상을
> 패킷+지표로 진단한 기록. "지연/손실이 났다"는 추측 대신 **재전송·RTT·p99로 원인을 짚는** 과정.
> 다루는 것: tcpdump/Wireshark, **L4(TCP) 트러블슈팅**, `tc netem`, 재전송/흐름제어/RTT.
>
> 산출물: `netem-before.pcap`(정상)·`netem-after.pcap`(주입). 재현·필터는 아래 §재현/필터/분석, 검증맵은 §2.

---

## 0. 한눈에 — 이 실습이 증명한 것

1. **증상의 국소화 = 진단의 본질.** 재전송이 netem 건 링크(8083)에 **100% 몰리고** 정상 대조 링크(8084)는 **0** → "어느 구간이 문제인가"를 패킷만으로 짚는다.
2. **측정은 캡처 위치에 의존한다(가장 비자명).** pip egress에 건 100ms 지연이, 캡처 지점(pdp) 기준 **한 방향엔 안 보이고 반대 방향에만** RTT로 드러난다 — 같은 장애를 보는 각도가 결과를 바꾼다.
3. **재전송은 TCP지 TLS가 아니다.** mTLS는 L4 **위** 계층이라 L4 증상을 못 가린다 — payload만 암호문이고 TCP 헤더·재전송·ACK는 평문으로 다 보인다.
4. **손실은 pcap에 안 찍힌다.** 버려진 패킷이 아니라 그 뒤의 **재전송·`lost_segment`·중복 ACK**가 손실의 증거다.

---

## 1. 어떻게 걸었나 — 캡처와 같은 메커니즘 + 권한 한 줄

앱이 컨테이너라 호스트에서 `tc`를 못 건다. 그래서 netshoot를 대상 netns에
합류시키되(`--net container:<대상>`), qdisc를 바꿀 권한(`--cap-add NET_ADMIN`)만 더했다.

```bash
docker run --rm --net container:ztg-pip --cap-add NET_ADMIN nicolaka/netshoot \
  tc qdisc replace dev eth0 root netem delay 100ms 20ms loss 5%
```

대상을 체인 말단 **pip**으로 둔 이유: 영향 링크가 `pdp↔pip`(8083) 하나로 깔끔하고, **실습1과 같은 pdp
netns vantage**로 그대로 관측된다. netem은 root qdisc=eth0 **송신(egress)** 에 걸려 pip의 응답이 지연/유실된다.

> 측정 함정: 게이트웨이 결정 캐시가 켜져 있으면 캐시히트가 pip 호출을 건너뛰어 L4 영향이 안 보인다 →
> 측정 시 캐시 OFF로 매 요청이 전 체인을 타게 했다. (자세한 재현/필터는 아래 §재현/필터/분석.)

---

## 2. 검증맵 (tshark 객관 사실, before vs after)

| 지표 | before(정상) | after(netem 100ms±20ms, loss 5%) |
| --- | --- | --- |
| 8083 재전송 | **0** | **107** |
| 8084 (주입 안 한 대조 링크) 재전송 | 0~1 | **0** |
| fast retransmission / duplicate ACK | 0 / 0 | **80 / 275** |
| 8083 `ack_rtt` avg / p99 / max | 0.1 / 0.5 / 43 ms | **55.7 / 230 / 1116 ms** |
| e2e `/api/hello` p50 / p99 | 14.5 / 39.5 ms | **357.9 / 1564 ms (≈40배)** |
| netem 드롭 카운터 | — | **169 / 3,346 = 5.05%** (설정 5%와 일치) |

**TCP가 손실을 재전송으로 복구**해 손실 5%에도 180/180 요청이 끝내 200(실패 0) = "느리지만 안 끊김"이라는
현실 장애 양상. 재전송이 e2e p99를 40배로 끌어올린 게 "L4 증상이 SLO 지표로 번지는" 한 그림.

---

## 3. 100ms가 한 방향에만 보인다

netem `delay 100ms`는 **pip의 egress**에 걸려 있다. 캡처 지점은 pdp.

- **pip→pdp 방향:** pip 데이터는 **이미 100ms 지연된 뒤** pdp에 도착하고 pdp는 즉시 ACK한다. Wireshark RTT는
  "데이터 본 시각→ACK 본 시각"이라 **100ms가 이미 소모돼 안 잡힌다**(RTT 그래프 max ~30ms).
- **pdp→pip 방향:** pdp 요청에 대한 pip의 **ACK가 netem egress로 100ms 늦게** 온다 → RTT가 **100ms대로 점프**.

→ Wireshark `방향 전환` 한 번으로 같은 연결의 RTT가 ms 미만 ↔ 100ms대를 오간다. **"장애 지점 대비 캡처
위치에 따라 같은 지연이 한 방향에만 드러난다"** — L4 측정이 vantage 의존임을 보여주는 한 컷.
(연결의 `iRTT`가 이미 ~117ms인 것도, 핸드셰이크 자체가 netem 하에서 일어난 흔적.)

---

## 4. 손실복구 한 사이클을 패킷으로 따라가기

netem이 버린 세그먼트는 캡처에 없다. 대신 그 **결과**가 순서대로 찍힌다:

```
(손실: netem drop — pcap에 없음)
[TCP Previous segment not captured]   ← 다음 세그먼트가 먼저 도착해 '구멍'을 드러냄 (tcp.analysis.lost_segment)
Duplicate ACK #1 · #2 · #3            ← 수신측(pdp)이 "빠진 거 있다"를 반복 통보
[TCP Fast Retransmission]             ← 송신측(pip)이 dup ACK 3개 받고 8ms 만에 재전송 (RTO ~117ms 안 기다림)
```

`Fast Retransmission`엔 RTO 필드가 없다 — **타임아웃이 아니라 중복 ACK 3개로 촉발**됐기 때문(없는 게 정상).
RTO 기반 재전송(`tcp.analysis.retransmission && !fast_retransmission`)을 보면 `[RTO based on delta from frame N]`로
원본↔재전송이 연결되고 시간 간격이 100ms+로 벌어진다 — **fast(8ms) vs timeout(100ms+)** 의 대비.

---

## 5. 제로트러스트와의 관계

이 실습은 제로트러스트 **원리**를 입증하는 게 아니다 — L4 재전송·RTT는 **성능·관측·트러블슈팅 역량**이다
(JD 우대: L2~L4, tcpdump/Wireshark). 다만 netem을 건 `pdp↔pip`은 **정책 시행 경로 그 자체**라, 한 발 더
디디면 *"정책 경로가 네트워크로 열화될 때 인가가 fail-close로 안전하게 degrade되는가(가용성=보안 속성)"* 로
이어진다. 이번엔 TCP가 복구해 fail-close가 트리거되진 않았고, 더 가혹한 주입(타임아웃 유발)으로
**열화→DENY 전이**를 잡는 게 확장 후보다.

---

## 재현 / 필터 / 분석

**재현 (cold start, 캐시 OFF 측정):** 게이트웨이를 결정 캐시 OFF로 재생성한 뒤 before/after를 각각 캡처+부하한다.

- `docker/compose-netem.yml` — 게이트웨이 결정 캐시 OFF override(측정용). 캐시 ON이면 캐시히트가 pip 호출을 건너뛰어 L4 영향이 안 보인다.
- `docker/netem-capture.sh <before|after> [캡처초] [요청수]` — pdp netns에 tcpdump 사이드카 + curl 부하를 한 WSL 세션에 묶어 오케스트레이션(pcap 저장·p50/p90/p99 출력).
- `docker/netem-inject.ps1`(`-Show`로 드롭 통계)·`docker/netem-clear.ps1` — netem 주입/해제.

**Wireshark/tshark 필터:**

```text
tcp.analysis.retransmission        손실 재전송(핵심 증거)
tcp.analysis.fast_retransmission   중복 ACK 3개로 촉발된 빠른 재전송
tcp.analysis.duplicate_ack         "빠진 세그먼트 있음" 신호
tcp.analysis.lost_segment          다음 세그먼트가 먼저 도착해 드러난 '구멍'
tcp.analysis.ack_rtt               ACK까지 걸린 시간(주입 후 ≈100ms 점프)
tcp.port == 8083                   pdp↔pip(netem 건 링크) — 증상이 여기 몰린다
tcp.port == 8084                   gw↔pdp(대조: 주입 안 한 링크)
```

**검증맵:** §2 표(before vs after, tshark 객관 사실).
