# Zero Trust Access Gateway

Keycloak과 직접 구현한 정책엔진(PDP/PIP)으로 제로트러스트 접근제어를 구성한 프로젝트다.
NIST SP 800-207의 표준 컴포넌트(PEP·PDP·PIP)를 Java/Spring 멀티모듈로 분리 구현했고,
로그인 시점의 1회 인증에서 끝나지 않고 세션 중에도 위험 신호를 반영해 접근을 회수하는
지속검증(continuous & risk-adaptive authorization)까지 다룬다. 같은 세션에서 새 IP나
요청 폭주가 관측되면 재로그인 없이 다음 요청부터 결정이 ALLOW에서 DENY로 바뀐다.

---

## 1. 문제 정의

제로트러스트는 "한 번 인증하면 끝"이 아니라, 누가 무엇을 어떤 조건에서 접근하는지 계속
판단하고 그 판단이 실제 트래픽 제어로 이어져야 한다는 모델이다. 이 프로젝트는 그 표준
구조를 컴포넌트 단위로 나눠 구현한다.

| 표준 용어 (NIST SP 800-207) | 역할 | 이 프로젝트의 모듈 |
|---|---|---|
| PEP (Policy Enforcement Point) / Data Plane | 트래픽을 가로채 허용·차단을 집행 | `gateway` (Spring Cloud Gateway) |
| PDP (Policy Decision Point) | 허용/거부를 판단 | `pdp` |
| PIP (Policy Information Point) | 판단에 필요한 맥락·위험점수 제공 | `pip` |
| IdP | "누가"를 증명 (로그인 → JWT) | Keycloak (Docker) |
| Resource | 실제 보호 대상 백엔드 | `resource-api` |

---

## 2. 아키텍처

```
  ┌─────────┐  ① 로그인 → JWT 발급     ┌─────────────┐
  │ Client  │ ◀────────────────────▶ │  Keycloak   │  ← IdP (OIDC, JWT 발급)
  └────┬────┘                        └─────────────┘
       │ ② 요청(JWT)
       ▼
  ┌──────────────┐  ③ 판단요청    ┌──────────┐
  │   Gateway    │ ───────────▶ │   PDP    │
  │  (DP / PEP)  │ ◀─────────── │ 정책결정  │
  │ JWT 검증 +   │   허용/거부     └────┬─────┘
  │ 정책 enforce │                    │ ④ 속성·위험 조회
  │ (IP·레이트·   │                    ▼
  │  시각 관측)    │              ┌──────────┐
  └──────┬───────┘              │   PIP    │
         │ ⑤ 허용시 통과          │ 위험점수  │
         ▼                       │ 산출      │
  ┌──────────────┐              └──────────┘
  │ resource-api │
  │  (보호대상)   │
  └──────────────┘

검증 관계(다이어그램에는 생략, 흐름과 별개): Gateway와 resource-api는 각각 Keycloak의 JWKS로
JWT를 독립 검증한다(서명/iss/exp). resource-api는 realm role로 인가까지 수행
→ 게이트웨이를 우회한 직접호출도 막는 이중 검증. (위험신호 IP·레이트·시각은
Gateway가 관측해 전달하고, PIP가 받아 위험점수로 산출.)
```

요청 흐름을 따라가면 이렇다. Client가 Keycloak에서 JWT를 발급받아 요청에 싣는다.
Gateway는 매 요청마다 JWT를 검증한 뒤 PDP에 "이 사용자가 이 리소스에 접근 가능한가"를
질의하고, PDP는 PIP에서 주체 속성과 동적 위험점수를 받아 정책을 평가한다. 허용이면
`resource-api`로 통과시키고 거부면 403을 반환한다. `resource-api`는 통과된 요청도 JWT를
한 번 더 독립 검증하고 realm role로 인가하며, 내부 신뢰헤더와 mTLS로 게이트웨이를 우회한
직접호출까지 차단한다.

### 모듈 구성 (Gradle 멀티모듈)

```
zero-trust-gateway/
├── gateway/        # DP/PEP — JWT 검증, PDP 질의, 결정 캐시, 레이트 관측, fan-out 구독
├── pdp/            # 정책 결정 — ABAC(deny-overrides) + 위험 임계 판정
├── pip/            # 정책 정보 — 주체 속성 저장 + 동적 위험점수 산출, epoch 발신
├── resource-api/   # 보호 대상 백엔드 (게이트웨이 경유만 허용)
├── common/         # 모듈 간 DTO (Decision·Risk·Fanout 등)
└── docker/         # docker-compose, Keycloak realm, prometheus/grafana, 스모크·부하 스크립트
```

---

## 3. 기술 스택

- **언어/빌드:** Java 21 · Gradle 멀티모듈
- **프레임워크:** Spring Boot 3.3
- **Gateway(DP):** Spring Cloud Gateway (리액티브 GlobalFilter로 enforce)
- **인증:** Spring Security Resource Server (JWT 검증, JWKS)
- **IdP:** Keycloak 26 (Docker, realm `ztg`)
- **정책엔진(PDP):** Java ABAC 엔진 (deny-overrides, 조건/임계 전부 설정화)
- **PIP 저장소:** in-memory 속성 + 휘발성 위험 신호
- **관측성:** Micrometer + Prometheus + Grafana, 요청 추적 ID(MDC) 상관
- **부하테스트:** k6
- **fan-out:** Redis pub/sub (다중 게이트웨이 캐시 무효화)
- **인프라:** Docker Compose

---

## 4. 지속검증 / 위험적응 인가

인증 데모는 대부분 로그인 시점의 허용에서 끝난다. 이 프로젝트는 세션이 살아있는 동안에도
위험이 바뀌면 접근을 회수하는 것을 목표로 잡았고, 아래 네 가지가 그 구현이다.

### 4.1 설명 가능한 동적 위험점수 (PIP)

`RiskEngine`은 아래 신호들을 가중합해 0~100 점수로 환산하고, 각 신호의 기여분을 점수와
함께 반환한다. 거부 응답에 "왜 막혔는지"를 실을 수 있게 하기 위해서다.

| 신호 | 의미 | 기본 가중치 |
|---|---|---|
| `baseline` | 주체 기본 신뢰도 (등록 사용자 낮음 / 미등록 높음) | 주체별 |
| `device-untrusted` | 관리되지 않는 단말 | 40 |
| `ip-change` | 직전 관측과 다른 출발지 IP (이동·탈취 신호) | 30 |
| `rate-burst` | 슬라이딩 윈도우 내 요청수가 임계 초과 (폭주·스크래핑) | 40 |
| `off-hours` | 업무시간 외 접근 | 15 |

가중치와 임계값은 모두 설정으로 빼 두어, 코드 수정 없이 조건만 바꿔 ALLOW/DENY 결과를
뒤집어 볼 수 있다.

> **한계 (의도된 단순화):** 출발지 IP는 `X-Forwarded-For` 첫 홉을 그대로 신뢰한다.
> 데모에서 IP 변화를 주입해 시연하기 위한 구조로, 클라이언트가 이 헤더를 위조하면
> `ip-change` 탐지를 우회할 수 있다. 운영 환경이라면 신뢰 프록시(로드밸런서)가 부여한
> 값만 수용하고 클라이언트 제공분은 제거해야 한다.

### 4.2 정책 결정 (PDP)

`PolicyEngine`은 deny-overrides 모델로 평가한다. 위험점수가 임계값(`risk-threshold`,
기본 80) 이상이면 리소스와 무관하게 거부하고, `payroll` 리소스는 finance 부서·업무시간·
신뢰 디바이스 조건을 모두 만족할 때만 허용하며, 그 외에는 기본 허용이다. 거부 사유에는
점수 기여 내역을 그대로 실어, 응답과 로그에서 차단 원인을 확인할 수 있다.

### 4.3 능동 캐시 무효화

게이트웨이는 PDP 왕복을 줄이기 위해 결정을 짧게 캐싱한다. 그런데 단순 TTL만 쓰면 캐시된
ALLOW가 TTL 동안의 위험 상승을 무시하게 되어 지속검증과 정면으로 충돌한다. 그래서 캐시
무효화를 부가 기능이 아니라 핵심 메커니즘으로 설계했다.

- **위험적응 TTL** — 고위험 결정일수록 짧게 캐싱해 더 자주 재평가한다 (`ttl = f(riskScore)`).
- **레이트 밴드 트리거** — 요청 레이트가 폭주 밴드를 넘나드는 순간 캐시를 강제로 우회해 즉시 재평가를 유발한다.
  밴드가 바뀐 순간에만 발동하는 엣지 트리거라, 폭주가 지속되는 동안에는 캐시가 다시 동작한다
  (레벨 트리거였다면 폭주 내내 캐시가 무력화돼 성능 이점이 사라진다).
- **epoch 키-아웃** — PDP 결정에 주체별 위험 `epoch`를 실어 보내고, epoch가 오르면 게이트웨이가
  이전 세대의 캐시 결정을 즉시 무효화한다. 캐시 키를 그 결정이 운반한 epoch로 만들기 때문에,
  위험 전이 순간 뒤늦게 도착한 옛 세대의 stale ALLOW가 새 세대의 DENY를 덮어쓰지 못한다
  (옛 결정은 옛 세대 키에 고립돼 더는 조회되지 않는다).

이 세 장치 덕분에, 같은 토큰·같은 세션에서 새 IP나 폭주를 주입하면 재로그인 없이 다음
호출이 ALLOW에서 DENY로 전이한다. 실제로는 이렇게 보인다 (`smoke-d1.ps1`의 한 장면,
토큰은 처음 한 번만 발급):

```text
$ curl -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 203.0.113.10" :8080/api/hello
HTTP/1.1 200        # baseline 10 + device-untrusted 40 = 50 < 임계 80 → ALLOW

$ curl -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 198.51.100.66" :8080/api/hello
HTTP/1.1 403        # 같은 토큰, 낯선 IP → ip-change +30 = 80 ≥ 80 → DENY
X-Denied-Reason: risk score 80 >= threshold 80 [baseline(+10): stored baseline risk
  for subject alice; device-untrusted(+40): access from an untrusted (unmanaged)
  device; ip-change(+30): source ip changed 203.0.113.10 -> 198.51.100.66]
```

폭주 시나리오도 같은 구조다(rate-burst +40 → 90점 DENY). 위험이 가시면 — 레이트 윈도우가
비면 — 다음 재평가에서 다시 200으로 복귀한다. 영구 차단이 아니라 위험에 적응하는
가역적 결정이다.

### 4.4 다중 게이트웨이 fan-out (Redis pub/sub)

게이트웨이가 여러 대인 구성에서는 위험을 유발하지 않은 노드가 TTL 동안 옛 ALLOW를 캐시
히트로 낼 수 있다. 그래서 위험 정보의 권위자인 PIP가 epoch 상승 시 Redis 채널로 발행하고,
모든 게이트웨이가 이를 구독해 즉시 키-아웃한다.

- 기본값은 OFF다 (`ztg.fanout.enabled=false`). 단일 노드나 테스트 환경은 Redis 없이 동작한다.
- 전달 보장은 at-most-once로 충분하다고 판단했다. TTL과 lazy 학습이 백스톱이라 한 번 놓쳐도 곧 수렴하며, 가용성을 우선해 publish 실패는 무시한다.
- Kafka 대신 Redis pub/sub을 쓴 이유: 지속성·재생 요구가 없어 이 규모에는 과하다.

---

## 5. 운영 품질 (관측성 · 부하검증 · mTLS)

- **관측성:** 각 서비스가 `/actuator/prometheus`를 노출하고 Prometheus가 스크랩해 Grafana
  대시보드로 본다. PDP 호출 지연은 히스토그램으로 발행해 p99를 계산하고, 요청 추적 ID(MDC)로
  게이트웨이→PDP→PIP 로그를 같은 ID로 상관시킨다.
- **장애 안전:** PDP/PIP 호출 실패 시 fail-close(차단)를 기본값으로 선택했다. 라이브
  fail-close 스모크로 검증했다.
- **부하검증 (k6):** 결정 캐시 적용 전후를 같은 조건(VUs 50)으로 비교했다. 처리량
  +63%(9,010→14,681 rps), p99 −17%(12.7→10.5ms), 실패율 0%. 위험적응 TTL과 레이트 밴드
  강제 우회 같은 신선도 장치를 켠 상태에서도 정상 경로 캐시 히트율은 99.7%였고, 그중
  레이트 밴드 강제 우회는 180초 동안 3회에 그쳤다(나머지 0.3% 미스는 통상적인 TTL 만료와
  최초 채움). 보안을 위한 재평가가 정상 트래픽 성능을 거의 깎지 않음을 수치로 확인했다.
- **서비스간 mTLS:** 게이트웨이↔PDP↔PIP 내부 통신을 상호 TLS로 보호한다 (`compose-apps.yml`).

### 5.1 패킷레벨 관측 — mTLS를 와이어에서 확인

mTLS 적용 여부를 설정이나 로그가 아니라 tcpdump로 뜬 실제 패킷에서 확인했다.

- 컨테이너 간 mTLS 트래픽은 호스트 tcpdump에 잡히지 않아, pdp 컨테이너의 네트워크
  네임스페이스에 사이드카를 붙여 gw→pdp, pdp→pip 두 구간을 한 지점에서 캡처했다.
- 단방향 TLS에는 없는 CertificateRequest(handshake type 13) 메시지, 그리고 서버 `CN=pdp`·
  클라이언트 `CN=gateway` 인증서 교환을 캡처에서 확인했다.
- 처음에는 인증서가 보이지 않았는데, 기본 협상이 TLS 1.3이라 핸드셰이크 자체가 암호화되기
  때문이었다. 관측 구간만 1.2로 내려 확인했고, 두 캡처를 대비하면 1.3이 핸드셰이크
  메타데이터까지 가린다는 점도 함께 드러난다.
- 인증서 없는 우회 호출은 빈 Certificate 메시지 후 서버의 fatal Alert로 연결이 끊기는
  것까지 캡처했다.

정리 문서: [docs/packet-study/mtls-wire-study.md](docs/packet-study/mtls-wire-study.md)
(상세 재현 절차 수록)

### 5.2 L4 트러블슈팅 — 장애를 와이어에서 진단

정책 경로(pdp↔pip)에 `tc netem`으로 지연 100ms·손실 5%를 주입하고, 증상을 패킷과 지표로
추적했다.

- 재전송 카운트가 netem을 건 링크(8083)에서만 0→107로 늘고 주입하지 않은 8084는 0을
  유지해, 패킷만으로 문제 구간을 격리할 수 있었다. e2e p99는 39.5ms에서 1.56s로 약 40배
  악화됐다.
- pip egress에 건 100ms 지연이 캡처 지점(pdp) 기준으로는 한 방향에는 보이지 않고 반대
  방향의 RTT로만 드러났다. 같은 장애도 관측 지점(vantage)에 따라 다르게 보인다.
- 재전송은 TCP 계층의 동작이라 mTLS와 무관하게 그대로 관측된다. 암호화되는 것은
  payload뿐이고, L4 증상은 평문으로 다 보인다.

정리 문서: [docs/packet-study/l4-netem-study.md](docs/packet-study/l4-netem-study.md)
(재현 절차·필터·검증 맵 수록)

### 5.3 커널 레벨 트래픽 제어 — 위험 판단을 XDP 드랍으로 (eBPF/XDP)

위험 판단(PIP)의 결과를 L7 거부에서 멈추지 않고 커널(XDP)에서 패킷을 직접 버리는 데까지
이었다. 관측 지점과 제어 지점을 둘 다 L7에서 L3/4로 내린 것이다.

- **관측 하강:** 커널 XDP가 per-source-IP로 SYN을 세어 PIP에 밀어 넣는다. 토큰 없는 SYN
  플러드는 인증을 통과하지 못해 게이트웨이의 L7 레이트에는 안 잡히지만, 커널 L4 관측에는
  잡힌다. 플러드가 전부 401인데도 같은 세션이 ALLOW→DENY로 전이하는 것이 그 증거다.
- **제어 하강:** 판단은 PIP가 하고 집행만 커널이 한다. PIP가 위험 IP에 대한 차단 지시(deny+TTL)를
  내리면 사이드카가 커널 deny map에 기록하고, 그 IP의 패킷은 스택 진입 전에 드랍된다 —
  클라이언트는 403이 아니라 L4에서 끊긴다. TTL이 만료되면 커널이 스스로 통과시켜(fail-safe)
  오탐이 영구 차단으로 굳지 않는다.
- **상대 성능:** 같은 SYN 플러드에서 유저스페이스가 401로 처리하면 게이트웨이 CPU가 avg
  108%(peak 206%)까지 뛰지만, XDP가 스택 진입 전에 드랍하면 idle(0.2%)에 머문다. 커널 드랍이
  게이트웨이 CPU를 약 100% 덜어냈다(WSL 가상 환경이라 절대치가 아닌 상대 델타로만 해석).

이 축(IP 단위 에지 차단)은 §4의 세션 단위 무효화를 대체하는 것이 아니라, 판단을 더 낮은
계층으로 전파하는 별도 축이다. 정리 문서: [docs/packet-study/xdp-study.md](docs/packet-study/xdp-study.md)
(구조·측정·한계 수록)

---

## 6. 빠른 시작

> 환경: Docker(WSL) + Java 21. Windows는 `.\gradlew.bat`, 그 외 `./gradlew`.

```bash
# 1) IdP(Keycloak) 기동 — realm 'ztg' 자동 import
docker compose -f docker/docker-compose.yml up -d

# 2) 빌드 (전체 회귀)
./gradlew build

# 3) 핫패스 4개 서비스 기동 (각 모듈)
./gradlew :resource-api:bootRun   # :8082
./gradlew :pip:bootRun            # :8083
./gradlew :pdp:bootRun            # :8084
./gradlew :gateway:bootRun        # :8080  ← 외부 진입점

# 4) 토큰 발급 후 게이트웨이로 호출
#    (docker/get-token.sh 가 Keycloak에서 JWT를 받아온다)
TOKEN=$(./docker/get-token.sh)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/hello
```

| 서비스 | 포트 |
|---|---|
| gateway (진입점) | 8080 |
| keycloak | 8081 |
| resource-api | 8082 |
| pip | 8083 |
| pdp | 8084 |
| prometheus / grafana | 9090 / 3000 |

### 데모 스크립트 (`docker/`)

| 스크립트 | 보이는 것 |
|---|---|
| `smoke-phase2.ps1` | JWT 검증 + 게이트웨이 enforce |
| `smoke-phase3.ps1` | PDP/PIP 정책 분리 (payroll 조건부 허용) |
| `smoke-phase4-failclose.ps1` | PDP 장애 시 fail-close 차단 |
| `smoke-d1.ps1` | 재로그인 없이 ALLOW→DENY (새 IP·폭주 주입) |
| `smoke-d1-fanout.ps1` | 다중 GW Redis fan-out 무효화 |
| `smoke-mtls.ps1` | 서비스간 mTLS |
| `loadtest.js` (k6) | 캐시 before/after 처리량·p99 |

---

## 7. 검증

- **L2 단위:** 위험점수 가중합, 정책 결정(ALLOW/DENY), 캐시 epoch 키-아웃, fan-out 코덱 라운드트립.
- **L3 e2e:** 정상 호출 ALLOW → IP 변경/폭주 주입 → 다음 호출 DENY (재로그인 없이).
- 전체 회귀는 `./gradlew build` 하나로 수행한다 (검증 실패 = 빌드 실패).

```bash
./gradlew build           # 전체 회귀
./gradlew test            # 단위/슬라이스 테스트만
```

---

## 8. 설계 원칙

- **fail-close 기본값** — 보안 데모이므로 모호하면 차단을 택하고 이유를 기록한다.
- **조건의 설정화** — 위험 가중치·임계·업무시간을 전부 외부화해, 코드 수정 없이 결과를 뒤집어 보일 수 있다.
- **설명 가능한 인가** — 모든 DENY는 "왜"(기여 신호·점수)를 응답과 로그에 남긴다.
- **점수는 PIP, 임계는 PDP** — 정보 산출과 정책 적용의 책임을 분리한다.

---

## 9. 한계와 확장

의도적으로 단순화한 부분과, 거기서 자연스럽게 이어지는 확장 지점이다.

- **출발지 IP 신뢰** — `X-Forwarded-For` 첫 홉을 그대로 신뢰한다(§4.1의 한계 참조). 운영이라면
  신뢰 프록시(로드밸런서)가 부여한 값만 수용하고 클라이언트 제공분은 제거해야 한다.
- **PIP 저장소가 in-memory** — 재기동 시 속성·위험 신호가 소실되고 PIP 자체의 다중화가 없다.
  속성·epoch를 외부 저장소로 빼고 PIP를 수평 확장하는 것이 다음 단계다.
- **디바이스 신뢰가 정적 속성** — `device-untrusted`는 저장된 값일 뿐 실제 단말 상태(posture)
  연동이 없다. MDM/EDR 신호를 PIP의 입력으로 잇는 것이 제로트러스트의 다음 조각이다.
- **fail-close 열화 시나리오** — netem 지연·손실 주입에서는 TCP가 복구해 fail-close가 트리거되지
  않았다. 타임아웃을 유발하는 더 가혹한 주입으로 "정책 경로 열화 → DENY 전이"까지 잡는 것이
  확장 후보다 ([l4-netem-study.md §5](docs/packet-study/l4-netem-study.md)).
