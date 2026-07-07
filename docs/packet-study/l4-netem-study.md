# L4 트러블슈팅을 와이어에서 — tc netem 장애주입·진단 기록

[실습1(mTLS 핸드셰이크 확인)](./mtls-wire-study.md)에 이어, 정책 경로(pdp↔pip)에 L4 장애를 인위로 주입하고 그
증상을 패킷과 지표로 진단한 기록이다. "지연이나 손실이 있는 것 같다"는 추측 대신
재전송·RTT·p99로 원인을 짚는 과정을 다룬다. 주제는 tcpdump/Wireshark, L4(TCP)
트러블슈팅, `tc netem`, 재전송/흐름제어/RTT.

산출물은 [netem-before.pcap](./netem-before.pcap)(정상)과 [netem-after.pcap](./netem-after.pcap)(주입)이다.
재현과 필터는 마지막 절, 검증 맵은 §2에 있다.

---

## 0. 요약

1. 진단의 핵심은 증상의 국소화다. 재전송이 netem을 건 링크(8083)에만 몰리고 정상 대조
   링크(8084)는 0이어서, 패킷만으로 문제 구간을 격리할 수 있다.
2. 측정은 캡처 위치에 의존한다. pip egress에 건 100ms 지연이 캡처 지점(pdp) 기준으로는
   한 방향에는 보이지 않고 반대 방향에만 RTT로 드러난다. 같은 장애도 보는 각도에 따라
   결과가 달라진다.
3. 재전송은 TCP의 동작이지 TLS의 동작이 아니다. mTLS는 L4 위 계층이라 L4 증상을 가리지
   못한다. 암호화되는 것은 payload뿐이고 TCP 헤더·재전송·ACK는 평문으로 다 보인다.
4. 손실 자체는 pcap에 찍히지 않는다. 버려진 패킷이 아니라 그 뒤에 오는
   재전송·`lost_segment`·중복 ACK가 손실의 증거다.

---

## 1. 주입 방법 — 캡처와 같은 메커니즘에 권한 한 줄

앱이 컨테이너라 호스트에서 `tc`를 걸 수 없다. 그래서 캡처와 같은 방식으로 netshoot를
대상 netns에 합류시키고(`--net container:<대상>`), qdisc를 바꿀 권한(`--cap-add NET_ADMIN`)만
더했다.

```bash
docker run --rm --net container:ztg-pip --cap-add NET_ADMIN nicolaka/netshoot \
  tc qdisc replace dev eth0 root netem delay 100ms 20ms loss 5%
```

대상을 체인 말단인 pip으로 둔 이유는 두 가지다. 영향 링크가 `pdp↔pip`(8083) 하나로
한정되어 깔끔하고, 실습1과 같은 pdp netns vantage로 그대로 관측할 수 있다. netem은
root qdisc로 eth0의 송신(egress)에 걸리므로 pip의 응답이 지연·유실된다.

> 측정 함정: 게이트웨이 결정 캐시가 켜져 있으면 캐시 히트가 pip 호출을 건너뛰어 L4
> 영향이 보이지 않는다. 측정 시에는 캐시를 끄고 매 요청이 전 체인을 타게 했다.
> (자세한 재현과 필터는 아래 §재현/필터/분석.)

---

## 2. 검증 맵 (tshark 측정치, before vs after)

| 지표 | before(정상) | after(netem 100ms±20ms, loss 5%) |
| --- | --- | --- |
| 8083 재전송 | 0 | **107** |
| 8084 (주입 안 한 대조 링크) 재전송 | 0~1 | **0** |
| fast retransmission / duplicate ACK | 0 / 0 | **80 / 275** |
| 8083 `ack_rtt` avg / p99 / max | 0.1 / 0.5 / 43 ms | **55.7 / 230 / 1116 ms** |
| e2e `/api/hello` p50 / p99 | 14.5 / 39.5 ms | **357.9 / 1564 ms (≈40배)** |
| netem 드롭 카운터 | — | **169 / 3,346 = 5.05%** (설정 5%와 일치) |

손실 5%에도 TCP가 재전송으로 복구해 180/180 요청이 결국 200으로 끝났다(실패 0).
"느리지만 끊기지 않는" 현실 장애의 전형적인 양상이고, 그 재전송이 e2e p99를 40배로
끌어올렸다. L4 증상이 SLO 지표로 번지는 경로가 이 표에 담겨 있다.

---

## 3. 100ms가 한 방향에만 보인다

netem `delay 100ms`는 pip의 egress에 걸려 있고, 캡처 지점은 pdp다.

- pip→pdp 방향: pip의 데이터는 이미 100ms 지연된 뒤에 pdp에 도착하고 pdp는 즉시
  ACK한다. Wireshark의 RTT는 "데이터를 본 시각→ACK를 본 시각"이라 100ms가 이미 소모된
  뒤여서 잡히지 않는다(RTT 그래프 max ~30ms).
- pdp→pip 방향: pdp의 요청에 대한 pip의 ACK가 netem egress를 지나며 100ms 늦게 온다.
  그래서 RTT가 100ms대로 점프한다.

Wireshark에서 방향 전환 한 번으로 같은 연결의 RTT가 ms 미만과 100ms대를 오간다. 장애
지점 대비 캡처 위치에 따라 같은 지연이 한 방향에만 드러나는 것으로, L4 측정이 vantage에
의존한다는 것을 보여주는 장면이다. (연결의 `iRTT`가 이미 ~117ms인 것도 핸드셰이크 자체가
netem 하에서 일어난 흔적이다.)

---

## 4. 손실 복구 한 사이클을 패킷으로 따라가기

netem이 버린 세그먼트는 캡처에 없다. 대신 그 결과가 순서대로 찍힌다.

```
(손실: netem drop — pcap에 없음)
[TCP Previous segment not captured]   ← 다음 세그먼트가 먼저 도착해 '구멍'을 드러냄 (tcp.analysis.lost_segment)
Duplicate ACK #1 · #2 · #3            ← 수신측(pdp)이 "빠진 거 있다"를 반복 통보
[TCP Fast Retransmission]             ← 송신측(pip)이 dup ACK 3개 받고 8ms 만에 재전송 (RTO ~117ms 안 기다림)
```

`Fast Retransmission`에는 RTO 필드가 없는데, 타임아웃이 아니라 중복 ACK 3개로 촉발됐기
때문이다(없는 것이 정상이다). RTO 기반 재전송
(`tcp.analysis.retransmission && !fast_retransmission`)을 보면
`[RTO based on delta from frame N]`으로 원본과 재전송이 연결되고 시간 간격이 100ms
이상으로 벌어진다. fast(8ms)와 timeout(100ms+)의 대비가 그대로 보인다.

---

## 5. 제로트러스트와의 관계

이 실습이 제로트러스트 원리를 입증하는 것은 아니다. L4 재전송·RTT 분석은 성능·관측·
트러블슈팅 역량에 해당한다. 다만 netem을 건 `pdp↔pip`은 정책 시행 경로 그 자체라, 한 발
더 디디면 "정책 경로가 네트워크 장애로 열화될 때 인가가 fail-close로 안전하게
degrade되는가"라는 질문(가용성을 보안 속성으로 보는 관점)으로 이어진다. 이번 주입에서는
TCP가 복구해 fail-close가 트리거되지 않았고, 타임아웃을 유발하는 더 가혹한 주입으로
열화→DENY 전이를 잡는 것이 확장 후보다.

---

## 재현 / 필터 / 분석

**재현 (cold start, 캐시 OFF 측정):** 게이트웨이를 결정 캐시 OFF로 재생성한 뒤
before/after를 각각 캡처+부하한다.

- `docker/compose-netem.yml` — 게이트웨이 결정 캐시 OFF override(측정용). 캐시 ON이면
  캐시 히트가 pip 호출을 건너뛰어 L4 영향이 보이지 않는다.
- `docker/netem-capture.sh <before|after> [캡처초] [요청수]` — pdp netns에 tcpdump
  사이드카 + curl 부하를 한 WSL 세션에 묶어 오케스트레이션(pcap 저장, p50/p90/p99 출력).
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

**검증 맵:** §2 표(before vs after, tshark 측정치).
