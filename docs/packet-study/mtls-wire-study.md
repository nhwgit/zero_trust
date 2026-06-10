# 서비스간 mTLS를 "와이어에서" 입증하기 — 패킷 분석 실습 기록

> "mTLS 적용했다"는 설정 한 줄 주장 대신, **tcpdump로 실제 패킷을 떠서** 게이트웨이 뒤 내부
> 통신(gateway→pdp→pip)이 정말 상호 인증되는지 검증한 실습 전체 기록.
> 다루는 것: tcpdump/Wireshark, L2~L4 트러블슈팅, TLS/HTTPS·mTLS 핸드셰이크 분석.
>
> 산출물: `mtls-tls12.pcap`(핵심)·`mtls-tls13.pcap`(대조) · 재현/필터 레퍼런스 → [README.md](./README.md)

---

## 0. 한눈에 — 이 실습이 증명한 것

1. **mTLS의 결정적 증거 = CertificateRequest(handshake type 13)** — 단방향 TLS엔 없는 메시지. 서버 `CN=pdp`·클라 `CN=gateway` 인증서 양방향 교환까지 확인.
2. **TLS 1.3이 증거를 숨긴다(가장 큰 발견)** — 기본 협상은 1.3이고, 1.3은 ServerHello 이후 인증서·CertReq를 암호화해 와이어에서 안 보인다. 진단 후 관측 구간만 1.2로 내려 입증. 두 pcap 대비 = "현대 TLS는 메타데이터까지 가린다".
3. **zero-trust를 패킷으로** — 인증서 없는 우회 호출: 빈 Certificate → 서버 `fatal Alert(handshake_failure)`로 즉시 절단. 인증서 제시 시 통과.
4. **세션 재개까지 구분(L4)** — 일부 연결은 TLS 세션 재개(abbreviated)라 인증서 교환 생략. "재교환 여부는 연결 상태(풀/재개)에 달림"을 스트림별로 분리 관찰.

---

## 1. 어떻게 캡처했나 (tcpdump)

### 문제: 어디서 캡처해야 보이나
핫패스 4개는 컨테이너로 떠 서로 **도커 브리지**(서비스명 DNS)로 통신한다. 이 내부 mTLS는
컨테이너 밖(호스트 tcpdump)에선 **안 보인다.** → 캡처 지점을 **컨테이너 네트워크 안쪽**에 둬야 한다.

### vantage point = pdp의 네트워크 네임스페이스(netns)
`pdp`가 체인 한가운데(`gateway→pdp→pip`)라, 여기 한 곳에 서면 **들어오는 gw→pdp(8084)** 와
**나가는 pdp→pip(8083)** 를 **동시에** 잡는다. 캡처 컨테이너(netshoot)를 pdp의 netns에 **합류**시키는 게 핵심.

```bash
docker run --rm --net container:ztg-pdp nicolaka/netshoot \
  timeout 30 tcpdump -i any -U -w - 'tcp port 8084 or tcp port 8083' > mtls.pcap
```

| 조각 | 의미 |
| --- | --- |
| `--net container:ztg-pdp` | **새 컨테이너를 pdp의 netns에 합류** → pdp의 eth0를 그대로 캡처(핵심) |
| `nicolaka/netshoot` | tcpdump·tshark가 든 디버깅 이미지(호스트에 tcpdump 설치 불필요) |
| `timeout 30` | 30초 뒤 자동 종료 → 캡처 flush |
| `-i any` | netns 안 모든 인터페이스. cooked(LINUX_SLL2) 링크타입으로 기록 |
| `-U` | 패킷마다 즉시 flush(unbuffered) — 짧은 캡처 유실 방지 |
| `-w -` | pcap을 stdout으로 → 호스트 리다이렉트로 파일이 호스트에 떨어짐(볼륨 불필요) |
| `'tcp port 8084 or 8083'` | BPF 필터 — mTLS 데이터 포트만(관리포트·잡음 제외) |

**트리거:** 캡처 중 `smoke-mtls.ps1` 실행 → 정상 체인 + 우회차단 + 인증서 제시 = 핸드셰이크 여러 개 발생.

> ⚠️ tcpdump가 netns에 **바인딩되기 전에** 트리거하면 0 패킷이 된다. 사이드카가 떴는지
> (`docker ps --filter ancestor=nicolaka/netshoot`) 확인하고 몇 초 뒤 트리거할 것.

---

## 2. ★ 핵심 발견: TLS 1.3이 핸드셰이크를 가린다 → 1.2로 관측

처음 캡처(`mtls-tls13.pcap`)엔 ClientHello·ServerHello(type 1·2)만 평문이고 **인증서도 CertificateRequest도
안 보였다.** 원인은 **TLS 1.3**:

- 1.3은 ServerHello 이후 Certificate·**CertificateRequest**·CertificateVerify·Finished를 **전부 핸드셰이크
  트래픽 키로 암호화**한다 → 와이어에선 `Application Data`(암호문)로만 보인다.
- 캡처의 ServerHello에서 `supported_version = 0x0304`(=TLS 1.3)로 진단. 레코드 Version 필드는 호환용
  위장값 `0x0303`(=1.2)을 쓰지만 진짜 버전은 `supported_versions` 확장에서 협상된다.

그래서 mTLS를 **눈으로 입증**하려면 관측 구간을 TLS 1.2로 내려야 한다. **두 캡처의 대비**(1.3=가려짐 /
1.2=보임) 자체가 "현대 TLS는 인증서·메타데이터까지 가린다"는 학습 포인트다.

### TLS 1.2 강제 — 실제로 막혔던 함정
`server.ssl.enabled-protocols: TLSv1.2`를 줘도 **안 먹었다**(캡처에서 여전히 0x0304). 원인:
**SSL 번들(`server.ssl.bundle`)을 쓰면 그 설정이 무시**되고, 반드시 **번들 옵션**으로 줘야 한다 —
`spring.ssl.bundle.jks.<bundle>.options.enabled-protocols`. 하이픈 키(`ztg-pdp`)는 env 상대바인딩이
까다로워 `SPRING_APPLICATION_JSON`으로 주입했다(`docker/compose-tls12.yml`).
pdp의 `ztg-pdp` 번들은 8084(서버)+pdp→pip(클라) 양쪽에 쓰여, 이것만 1.2로 제한해도 캡처 대상이 전부 1.2가 된다.

> ⚠️ 데모/관측용 다운그레이드일 뿐, 평소 스택은 1.3 그대로 둔다.

---

## 3. 무엇을 입증했나 (검증 결과 — tshark)

`mtls-tls12.pcap`을 tshark로 검증한 객관 사실:

- **진짜 TLS 1.2** — ServerHello 7개 전부 `0x0303` + `supported_version` 비어있음(1.3 위장 아님).
  TLS 1.2 전용 메시지 ServerKeyExchange(12)·ServerHelloDone(14)·ClientKeyExchange(16) 존재로 재확인.
- **핸드셰이크 메시지 분포:** type 1×7, 2×7, **11×6**(서버+클라 인증서), 12×3, **13×3(CertificateRequest)**,
  14×3, 15×1, 16×3, 4×5(NewSessionTicket).
- **서버 인증서 `CN=pdp`** 평문 노출 — frame 51, SAN `pdp,localhost`, 발급자 `ztg-internal-ca`.
- **클라 인증서 `CN=gateway`** 평문 노출 — frame 53, SAN `gateway,localhost`.
- **CertificateRequest(type 13)** — frames 39/51/89, 모두 `8084`(pdp 서버)가 클라 인증서를 요구한 지점.

대조군 `mtls-tls13.pcap`: ServerHello 직후 ChangeCipherSpec → 이후 전부 암호문. `type 11/13/15` **0건**.

---

## 4. 연결(스트림) 지도 + 핸드셰이크 흐름

TLS 핸드셰이크는 **TCP 연결 하나당 1번** → ClientHello 개수 = 연결 개수. `smoke` 한 번이 여러 연결을
만들고, 캡처 전 예열 호출로 일부는 **세션 재개**됐다.

| stream | 포트 | 무엇 | 핸드셰이크 | 인증서 교환 |
| --- | --- | --- | --- | --- |
| 0 | 41244→8084 | gateway→pdp | CH → SH+**NST**(`2,4`) | **재개(축약)** — 없음 |
| 1 | 38986→8083 | pdp→pip | CH → SH+NST | 재개 — 없음 |
| **2** | 50514→8084 | (호스트)→pdp, **인증서 없음** | 풀(`2,11,12,13,14`) → 빈 cert | **거부**: frame 41 빈 cert → 42 Alert(40) |
| **3** | 50516→8084 | (호스트)→pdp, **인증서 제시** | 풀 → `11,16,15` | **성립**: frame 53 CN=gateway + CertVerify |
| 4 | 39002→8083 | pdp→pip | CH → SH+NST | 재개 |
| **5** | 50518→8084 | (호스트)→pdp, 인증서 없음 | 풀 → 빈 cert | 거부 |
| 6 | 39008→8083 | pdp→pip | CH → SH+NST | 재개 |

→ **풀 핸드셰이크 = stream 2·3·5**(`type 13` ×3). 재개된 연결은 인증서 단계를 건너뛴다(`type 4`=NewSessionTicket이 신호).

### TLS 1.2 풀 핸드셰이크 한 흐름 (stream 3)
```
46·47·48  TCP SYN/SYN-ACK/ACK
49  CH         클라: ClientHello
51  SH+Cert+SKE+CertReq+SHD   서버 flight 한 패킷(2093B, type 2,11,12,13,14)  ← 서버 인증서 CN=pdp + "클라 인증서 내놔"
53  Cert+CKE+CertVerify       클라 flight(type 11,16,15)                       ← 클라 인증서 CN=gateway + 키소유 증명
54  NST(+CCS)  서버: New Session Ticket → 이후 Application Data(암호문)
```
서버는 응답을 **한 플라이트로 연달아** 보내므로(ServerHello~ServerHelloDone) 인증서가 작으면 한 TCP
세그먼트에 다 실린다 → Wireshark Info 칼럼이 "Server Hello, Certificate, …, Server Hello Done"으로
**한 줄에 합쳐져** 보인다("Server Hello"만 적힌 줄이 따로 없는 이유).

---

## 5. 와이어로 본 zero-trust (우회 차단)

인증서 없이 pdp:8084를 직접 호출한 stream 2:

```
frame 41  50514 → 8084   Certificate(type 11) + ClientKeyExchange(16),  certificates_length = 0  ← 빈 인증서!
frame 42  8084 → 50514   TLS Alert,  level=2(fatal),  desc=40(handshake_failure)               ← 서버가 즉시 절단
```

서버가 CertificateRequest로 인증서를 요구했으니 클라는 응답은 해야 해서 **빈 인증서 목록**을 보내고,
`client-auth: need`인 서버는 그걸 받자마자 **치명적 Alert**로 핸드셰이크를 끊는다. 이게 "와이어에서 본
우회 차단"이다.

### 서버 인증서 vs 클라 인증서 (방향이 반대인 두 신원 증명)

| | 서버 인증서(frame 51) | 클라 인증서(frame 53) |
| --- | --- | --- |
| 증명 | "나는 **pdp**" → 클라가 검증 | "나는 **gateway**" → 서버가 검증 |
| Subject CN / SAN | pdp / `pdp,localhost` | gateway / `gateway,localhost` |
| 체인 | **2장**(leaf pdp + CA) | **1장**(leaf만) |
| 키소유 증명 | **ServerKeyExchange(12)** 서명 | **CertificateVerify(15)** 서명 |
| 언제 | ServerHello 뒤 **항상**(단방향 TLS도) | **CertificateRequest 응답으로만**(mTLS) |

둘 다 발급자 `ztg-internal-ca`(공유 신뢰 앵커). **클라 인증서가 추가되는 것 = mTLS의 본질.**
인증서(공개키) 제출 + 서명(키소유 증명)이 한 쌍이라, 인증서만 훔쳐선 통과 못 한다.

---

## 6. 트리거 — `smoke-mtls.ps1`이 만든 3 시나리오

캡처는 손대지 않았다. 트리거 스크립트가 **3 시나리오를 일부러** 던지고 그게 스트림으로 잡혔을 뿐(설계).

- ① **정상 경로** — 토큰으로 gateway `/api/hello`→200 (내부 gw→pdp→pip mTLS, stream 0·1로 관측).
- ② **우회 차단** — 인증서 **없이** pdp:8084 직접 호출 → 거부되어야 PASS (**stream 2/5**, 빈 cert→Alert).
- ③ **대조군** — `gateway.p12` **제시** → TLS 성립이면 PASS (**stream 3**, CN=gateway).

②와 ③은 **요청 동일·인증서 유무만 다름** → "인증서가 접근을 가른다"(zero-trust) 입증.
(서버 인증서 검증은 자체 CA가 OS 신뢰저장소에 없어 일부러 우회 — 초점이 클라 인증서라서. `finally`에서 원복.)

---

## 7. 읽다가 막힌 것들 (Q&A)

**Q1. 서버 응답 한 패킷에 ServerHello·Certificate·SKE·CertReq·SHD가 다 든 이유?**
TLS 1.2 서버는 응답을 한 플라이트로 연달아 보낸다. TCP는 바이트 스트림이라 인증서가 작으면 다섯 메시지가
한 TCP 세그먼트에 실린다. 체인이 컸다면 여러 세그먼트로 쪼개져 Wireshark가 "TCP segment of a reassembled
PDU"로 재조립해 마지막에 펼쳐 보여줬을 것. → 이 한 패킷이 "서버가 mTLS를 요구하는 순간 전체"라 mTLS 입증의 핵심 증거.

**Q2. 서버 Certificate에서 rdnSequence가 4개인 이유?**
Certificate는 인증서 한 장이 아니라 **체인(목록)** 을 싣는다(여기선 2장: leaf=pdp, CA=ztg-internal-ca).
X.509 본문은 `Name` 필드가 둘 — `issuer` + `subject` — 이고 ASN.1상 둘 다 `rdnSequence`. → 인증서 1장당
2개(issuer,subject) × 2장 = 4개. (한 DN 안의 `2 items`는 또 별개 — `O=ztg` + `CN=...` 두 속성.)
신뢰 체인: 각 인증서의 issuer를 다음 인증서의 subject에 이어 붙이면 `leaf(pdp)→CA(ztg-internal-ca, self-signed)`
경로가 된다. CertificateRequest 아래 `Distinguished Name: CN=ztg-internal-ca`는 또 별개 = **수락 가능 CA 목록**.

**Q3. (1.3) ServerHello 직후 Change Cipher Spec이 오고, Version이 `TLS 1.2(0x0303)`인 이유?**
둘 다 1.3의 **미들박스 호환 위장**이다. CCS는 1.3에서 암호학적으로 아무 일도 안 하는 **더미**(옛 방화벽이
1.2 세션으로 오인해 통과시키게). 레코드 Version도 일부러 옛 값 0x0303을 쓰고, 진짜 버전(0x0304)은
`supported_versions`에서 협상한다. 그래서 열엔 "TLSv1.3", 레코드 안엔 "0x0303"이 동시에 보인다 — 모순 아님.

**Q4. `tls.handshake.type==13`이 stream 0·1엔 없고 2부터 잡히는 이유?**
인증서 교환 여부는 "연결 번호"가 아니라 그 연결이 **풀이냐 재개냐**에 달렸다. stream 0·1은 캡처 전 예열로
맺어둔 세션을 **재개**(ServerHello 직후 NewSessionTicket, 인증서 생략)했고, stream 2·3·5는 **풀 핸드셰이크**라
CertificateRequest·인증서가 다 나온다. 재개는 이미 인증된 세션 재사용이라 인증서를 다시 안 보낸다(오히려 덜 함).

---

## 8. 재현 (cold start)

```powershell
.\docker\up-mtls-docker.ps1                          # 스택 기동(기본 = TLS 1.3)
# (A) TLS 1.3 대조 캡처
.\docker\capture-mtls.ps1 -OutFile mtls-tls13.pcap   # 캡처 시작 → 사이드카 뜬 뒤
.\docker\smoke-mtls.ps1                              #   다른 창에서 트리거
# (B) TLS 1.2 강제 후 핵심 캡처
wsl -d Ubuntu-24.04 -- bash -c "cd /mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker && docker compose -f docker-compose.yml -f compose-apps.yml -f compose-tls12.yml up -d pdp pip"
.\docker\capture-mtls.ps1 -OutFile mtls-tls12.pcap   # 바인딩 확인 후 트리거
.\docker\smoke-mtls.ps1
.\docker\down-mtls-docker.ps1                         # 정리(Keycloak 유지)
```

### 핵심 Wireshark/tshark 필터
```
tls.handshake.type == 1/2/11/13/15   ClientHello/ServerHello/Certificate/CertificateRequest/CertificateVerify
tcp.port == 8084 / 8083              gateway→pdp / pdp→pip 데이터 구간
tcp.stream == N                      한 연결만
```
- 인증서 주체: `tshark -2 -r mtls-tls12.pcap -Y 'tls.handshake.type==11' -T fields -e x509sat.printableString`
- 1.3 대비: 같은 필터를 `mtls-tls13.pcap`에 걸면 type 11/13/15가 **0건**.

---

## 9. 산출물

- `mtls-tls12.pcap` — mTLS 핸드셰이크 평문(type 11/13/15, 서버·클라 인증서)
- `mtls-tls13.pcap` — 대조군(ServerHello 이후 암호화)
- `docker/compose-tls12.yml` — TLS 1.2 강제(번들 옵션) override
- [README.md](./README.md) — 재현·필터·검증맵 레퍼런스
