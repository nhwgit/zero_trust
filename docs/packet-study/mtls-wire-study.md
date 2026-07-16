# 서비스간 mTLS를 와이어에서 확인하기 — 패킷 분석 기록

"mTLS 적용했다"를 설정 한 줄로 주장하는 대신, tcpdump로 실제 패킷을 떠서 게이트웨이 뒤
내부 통신(gateway→pdp→pip)이 정말 상호 인증되는지 확인한 기록이다. tcpdump/Wireshark
사용법과 TLS/mTLS 핸드셰이크 분석을 다룬다.

산출물은 [mtls-tls12.pcap](./mtls-tls12.pcap)(핵심)과 [mtls-tls13.pcap](./mtls-tls13.pcap)(대조)이다.
재현 절차는 §7, Wireshark/tshark 필터는 §7에 있다.

---

## 0. 요약

1. mTLS의 증거는 CertificateRequest(handshake type 13)다. 단방향 TLS에는 없는 메시지로,
   서버 `CN=pdp`와 클라이언트 `CN=gateway`의 양방향 인증서 교환까지 캡처에서 확인했다.
2. TLS 1.3에서는 이 증거가 보이지 않는다. 기본 협상이 1.3인데, 1.3은 ServerHello 이후의
   인증서와 CertificateRequest를 암호화하기 때문이다. 원인을 진단한 뒤 관측 구간만 1.2로
   내려 확인했고, 두 pcap의 대비 자체가 "현대 TLS는 핸드셰이크 메타데이터까지 가린다"는
   것을 보여준다.
3. 인증서 없는 우회 호출은 빈 Certificate 메시지 뒤 서버의 fatal Alert(handshake_failure)로
   즉시 끊기고, 인증서를 제시하면 통과한다. 제로트러스트의 "인증서가 접근을 가른다"를
   패킷 수준에서 확인한 셈이다.
4. 일부 연결은 TLS 세션 재개(abbreviated handshake)라 인증서 교환이 생략된다. 인증서
   재교환 여부는 연결이 풀 핸드셰이크냐 재개냐에 달렸다는 점을 스트림별로 분리해 관찰했다.

---

## 1. 캡처 방법 (tcpdump)

### 캡처 지점 선정

핫패스 4개 서비스는 컨테이너로 떠서 도커 브리지(서비스명 DNS)로 통신한다. 이 내부 mTLS
트래픽은 컨테이너 밖 호스트의 tcpdump에는 잡히지 않으므로, 캡처 지점을 컨테이너 네트워크
안쪽에 둬야 한다.

pdp가 체인 한가운데(gateway→pdp→pip)에 있어, pdp의 네트워크 네임스페이스(netns)에 서면
들어오는 gw→pdp(8084)와 나가는 pdp→pip(8083)를 한 지점에서 동시에 잡을 수 있다. 캡처
컨테이너(netshoot)를 pdp의 netns에 합류시키는 방식이다.

```bash
docker run --rm --net container:ztg-pdp nicolaka/netshoot \
  timeout 30 tcpdump -i any -U -w - 'tcp port 8084 or tcp port 8083' > mtls.pcap
```

| 조각 | 의미 |
| --- | --- |
| `--net container:ztg-pdp` | 새 컨테이너를 pdp의 netns에 합류시켜 pdp의 eth0를 그대로 캡처 (이 방식의 핵심) |
| `nicolaka/netshoot` | tcpdump·tshark가 든 디버깅 이미지. 호스트에 tcpdump를 설치할 필요가 없다 |
| `timeout 30` | 30초 뒤 자동 종료해 캡처를 flush |
| `-i any` | netns 안 모든 인터페이스. cooked(LINUX_SLL2) 링크타입으로 기록된다 |
| `-U` | 패킷마다 즉시 flush(unbuffered). 짧은 캡처의 유실을 막는다 |
| `-w -` | pcap을 stdout으로 내보내 호스트 리다이렉트로 저장(볼륨 마운트 불필요) |
| `'tcp port 8084 or 8083'` | BPF 필터 — mTLS 데이터 포트만 남기고 관리포트·잡음 제외 |

트리거는 캡처 중에 `smoke-mtls.ps1`을 실행하는 것으로 충분하다. 정상 체인, 우회 차단,
인증서 제시의 세 시나리오가 핸드셰이크 여러 개를 만든다.

> 주의: tcpdump가 netns에 바인딩되기 전에 트리거하면 0 패킷이 된다. 사이드카가 떴는지
> (`docker ps --filter ancestor=nicolaka/netshoot`) 확인하고 몇 초 뒤에 트리거할 것.

---

## 2. TLS 1.3이 핸드셰이크를 가린다 — 1.2로 내려 관측

처음 캡처(`mtls-tls13.pcap`)에는 ClientHello·ServerHello(type 1·2)만 평문이고 인증서도
CertificateRequest도 보이지 않았다. 원인은 TLS 1.3이었다.

- 1.3은 ServerHello 이후의 Certificate·CertificateRequest·CertificateVerify·Finished를 전부
  핸드셰이크 트래픽 키로 암호화한다. 와이어에서는 `Application Data`(암호문)로만 보인다.
- 캡처의 ServerHello에서 `supported_version = 0x0304`(TLS 1.3)를 보고 진단했다. 레코드의
  Version 필드는 호환용 위장값 `0x0303`(1.2)을 쓰고, 진짜 버전은 `supported_versions`
  확장에서 협상된다.
- ServerHello 직후 보이는 ChangeCipherSpec도 같은 미들박스 호환 위장이다. 1.3에서 CCS는
  암호학적으로 아무 일도 하지 않는 더미로, 옛 장비가 1.2 세션으로 오인해 통과시키게 한다.
  그래서 목록 열에는 "TLSv1.3", 레코드 안에는 "0x0303"이 동시에 보인다 — 모순이 아니다.

그래서 mTLS 핸드셰이크를 평문으로 보려면 관측 구간을 TLS 1.2로 내려야 했다. 결과적으로
두 캡처의 대비(1.3에서는 가려지고 1.2에서는 보인다)가 그대로 학습 포인트가 됐다.

### TLS 1.2 강제에서 막힌 지점

`server.ssl.enabled-protocols: TLSv1.2`를 줘도 적용되지 않았다(캡처에서 여전히 0x0304).
SSL 번들(`server.ssl.bundle`)을 쓰면 그 설정이 무시되고, 번들 옵션인
`spring.ssl.bundle.jks.<bundle>.options.enabled-protocols`로 줘야 한다. 하이픈이 든
키(`ztg-pdp`)는 환경변수 상대 바인딩이 까다로워 `SPRING_APPLICATION_JSON`으로 주입했다
(`docker/compose-tls12.yml`). pdp의 `ztg-pdp` 번들은 8084(서버)와 pdp→pip(클라이언트)
양쪽에 쓰이므로, 이것만 1.2로 제한해도 캡처 대상이 전부 1.2가 된다.

관측용 다운그레이드일 뿐이며, 평소 스택은 1.3 그대로 둔다.

---

## 3. 검증 결과 (tshark)

`mtls-tls12.pcap`을 tshark로 검증한 사실들:

- 진짜 TLS 1.2다 — ServerHello 7개 전부 `0x0303`이고 `supported_version`이 비어 있다
  (1.3 위장이 아님). TLS 1.2 전용 메시지인 ServerKeyExchange(12)·ServerHelloDone(14)·
  ClientKeyExchange(16)의 존재로 재확인했다.
- 핸드셰이크 메시지 분포: type 1×7, 2×7, 11×6(서버+클라 인증서), 12×3,
  **13×3(CertificateRequest)**, 14×3, 15×1, 16×3, 4×5(NewSessionTicket).
- 서버 인증서 `CN=pdp`가 평문으로 노출된다 — frame 51, SAN `pdp,localhost`,
  발급자 `ztg-internal-ca`.
- 클라이언트 인증서 `CN=gateway`가 평문으로 노출된다 — frame 53, SAN `gateway,localhost`.
- CertificateRequest(type 13)는 frames 39/51/89. 모두 8084(pdp 서버)가 클라이언트
  인증서를 요구한 지점이다.

대조군 `mtls-tls13.pcap`에서는 ServerHello 직후 ChangeCipherSpec이 오고 이후 전부
암호문이다. type 11/13/15는 0건.

---

## 4. 연결(스트림) 지도와 핸드셰이크 흐름

TLS 핸드셰이크는 TCP 연결 하나당 한 번이므로 ClientHello 개수가 곧 연결 개수다. smoke
한 번이 여러 연결을 만들고, 캡처 전 예열 호출 덕에 일부 연결은 세션 재개로 처리됐다.

| stream | 포트 | 무엇 | 핸드셰이크 | 인증서 교환 |
| --- | --- | --- | --- | --- |
| 0 | 41244→8084 | gateway→pdp | CH → SH+NST(`2,4`) | 재개(축약) — 없음 |
| 1 | 38986→8083 | pdp→pip | CH → SH+NST | 재개 — 없음 |
| **2** | 50514→8084 | (호스트)→pdp, 인증서 없음 | 풀(`2,11,12,13,14`) → 빈 cert | 거부: frame 41 빈 cert → 42 Alert(40) |
| **3** | 50516→8084 | (호스트)→pdp, 인증서 제시 | 풀 → `11,16,15` | 성립: frame 53 CN=gateway + CertVerify |
| 4 | 39002→8083 | pdp→pip | CH → SH+NST | 재개 |
| **5** | 50518→8084 | (호스트)→pdp, 인증서 없음 | 풀 → 빈 cert | 거부 |
| 6 | 39008→8083 | pdp→pip | CH → SH+NST | 재개 |

풀 핸드셰이크는 stream 2·3·5(type 13이 3회)다. 재개된 연결은 인증서 단계를 건너뛰며,
NewSessionTicket(type 4)이 그 신호다.

### TLS 1.2 풀 핸드셰이크 한 흐름 (stream 3)

```text
46·47·48  TCP SYN/SYN-ACK/ACK
49  CH         클라: ClientHello
51  SH+Cert+SKE+CertReq+SHD   서버 flight 한 패킷(2093B, type 2,11,12,13,14)  ← 서버 인증서 CN=pdp + "클라 인증서 내놔"
53  Cert+CKE+CertVerify       클라 flight(type 11,16,15)                       ← 클라 인증서 CN=gateway + 키소유 증명
54  NST(+CCS)  서버: New Session Ticket → 이후 Application Data(암호문)
```

서버는 응답(ServerHello부터 ServerHelloDone까지)을 한 플라이트로 연달아 보내므로,
인증서가 작으면 한 TCP 세그먼트에 다 실린다. Wireshark의 Info 칼럼이 "Server Hello,
Certificate, …, Server Hello Done"으로 한 줄에 합쳐져 보이는 이유다("Server Hello"만
적힌 줄이 따로 없다).

---

## 5. 우회 차단을 와이어로 보기

인증서 없이 pdp:8084를 직접 호출한 stream 2:

```text
frame 41  50514 → 8084   Certificate(type 11) + ClientKeyExchange(16),  certificates_length = 0  ← 빈 인증서!
frame 42  8084 → 50514   TLS Alert,  level=2(fatal),  desc=40(handshake_failure)               ← 서버가 즉시 절단
```

서버가 CertificateRequest로 인증서를 요구했으니 클라이언트는 응답은 해야 해서 빈 인증서
목록을 보내고, `client-auth: need`인 서버는 그것을 받자마자 치명적 Alert로 핸드셰이크를
끊는다. 우회 차단이 패킷에 이렇게 찍힌다.

### 서버 인증서 vs 클라이언트 인증서 (방향이 반대인 두 신원 증명)

| | 서버 인증서(frame 51) | 클라 인증서(frame 53) |
| --- | --- | --- |
| 증명 | "나는 pdp" → 클라가 검증 | "나는 gateway" → 서버가 검증 |
| Subject CN / SAN | pdp / `pdp,localhost` | gateway / `gateway,localhost` |
| 체인 | 2장(leaf pdp + CA) | 1장(leaf만) |
| 키소유 증명 | ServerKeyExchange(12) 서명 | CertificateVerify(15) 서명 |
| 언제 | ServerHello 뒤 항상(단방향 TLS도) | CertificateRequest 응답으로만(mTLS) |

둘 다 발급자는 `ztg-internal-ca`(공유 신뢰 앵커)다. Certificate 메시지는 인증서 한 장이
아니라 체인을 싣고, 각 인증서의 issuer를 다음 인증서의 subject에 이어 붙이면 신뢰 앵커까지
닿는다. 클라이언트 인증서가 추가되는 것이 mTLS의 본질이고, 인증서(공개키) 제출과
서명(키소유 증명)이 한 쌍이라 인증서만 훔쳐서는 통과하지 못한다.

---

## 6. 트리거 — `smoke-mtls.ps1`의 세 시나리오

캡처 자체에는 손대지 않았다. 트리거 스크립트가 세 시나리오를 의도적으로 던지고, 그것이
스트림으로 잡혔을 뿐이다.

- ① 정상 경로 — 토큰으로 gateway `/api/hello` 호출 → 200. 내부 gw→pdp→pip mTLS 체인이
  성립함을 확인한다 (stream 0·1로 관측).
- ② 우회 차단 — 인증서 없이 pdp:8084 직접 호출 → 거부되어야 PASS (stream 2/5, 빈
  cert → Alert).
- ③ 대조군 — `gateway.p12`를 제시한 같은 호출 → TLS 성립이면 PASS (stream 3, CN=gateway).

②와 ③은 요청이 동일하고 인증서 유무만 다르다. 이 대비가 "인증서가 접근을 가른다"는
것을 보여준다. (서버 인증서 검증은 자체 CA가 OS 신뢰저장소에 없어 의도적으로 우회했다 —
테스트 초점이 클라이언트 인증서라서다. `finally`에서 원복한다.)

---

## 7. 재현 (cold start)

```powershell
.\docker\up-mtls-docker.ps1                          # 스택 기동(기본 = TLS 1.3)
# (A) TLS 1.3 대조 캡처
.\docker\capture-mtls.ps1 -OutFile mtls-tls13.pcap   # 캡처 시작 → 사이드카 뜬 뒤
.\docker\smoke-mtls.ps1                              #   다른 창에서 트리거
# (B) TLS 1.2 강제 후 핵심 캡처
wsl -d Ubuntu-24.04 -- bash -c "cd <repo>/docker && docker compose -f docker-compose.yml -f compose-apps.yml -f compose-tls12.yml up -d pdp pip"
.\docker\capture-mtls.ps1 -OutFile mtls-tls12.pcap   # 바인딩 확인 후 트리거
.\docker\smoke-mtls.ps1
.\docker\down-mtls-docker.ps1                         # 정리(Keycloak 유지)
```

### 핵심 Wireshark/tshark 필터

```text
tls.handshake.type == 1/2/11/13/15   ClientHello/ServerHello/Certificate/CertificateRequest/CertificateVerify
tcp.port == 8084 / 8083              gateway→pdp / pdp→pip 데이터 구간
tcp.stream == N                      한 연결만
```

- 인증서 주체 확인: `tshark -2 -r mtls-tls12.pcap -Y 'tls.handshake.type==11' -T fields -e x509sat.printableString`
- 1.3 대비: 같은 필터를 `mtls-tls13.pcap`에 걸면 type 11/13/15가 0건이다.

---

## 8. 산출물

- [mtls-tls12.pcap](./mtls-tls12.pcap) — mTLS 핸드셰이크 평문(type 11/13/15, 서버·클라 인증서)
- [mtls-tls13.pcap](./mtls-tls13.pcap) — 대조군(ServerHello 이후 암호화)
- `docker/compose-tls12.yml` — TLS 1.2 강제(번들 옵션) override
- `docker/up-mtls-docker.ps1`·`capture-mtls.ps1`·`smoke-mtls.ps1` — 재현(기동·캡처·트리거) 스크립트 (§7 절차)
