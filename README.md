# Zero Trust Access Gateway

**Keycloak + 정책엔진(PDP/PIP)으로 제로트러스트 접근제어를 직접 구현한 포트폴리오.**
NIST SP 800-207의 표준 컴포넌트(PEP·PDP·PIP)를 Java/Spring으로 분리 구현하고,
단순 "1회 인증"을 넘어 **세션 중에도 위험을 지속 검증해 접근을 회수**하는 흐름까지 보인다.

> 핵심 차별점 — **지속검증 / 위험적응 인가(Continuous & Risk-Adaptive Authorization)**:
> 위험 신호(새 IP·요청 폭주 등)가 올라가면 **재로그인 없이** 같은 세션의 결정이 `ALLOW → DENY`로 뒤집힌다.

---

## 1. 무엇을 푸는가

제로트러스트의 본질은 "한 번 인증하면 끝"이 아니라 **"누가 / 무엇을 / 어떤 조건에서 접근하는지 계속 판단하고,
그 판단이 실제 트래픽 제어로 이어지는 것"**이다. 이 프로젝트는 그 표준 구조를 컴포넌트로 쪼개 구현한다.

| 표준 용어 (NIST SP 800-207) | 역할 | 이 프로젝트의 모듈 |
|---|---|---|
| **PEP** (Policy Enforcement Point) / Data Plane | 트래픽을 가로채 허용·차단을 **집행** | `gateway` (Spring Cloud Gateway) |
| **PDP** (Policy Decision Point) | 허용/거부를 **판단**하는 두뇌 | `pdp` |
| **PIP** (Policy Information Point) | 판단에 필요한 **맥락·위험점수** 제공 | `pip` |
| **IdP** | "누가"를 증명 (로그인 → JWT) | Keycloak (Docker) |
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

검증 관계(점선, 흐름과 별개): Gateway와 resource-api는 각각 Keycloak의 JWKS로
JWT를 독립 검증한다(서명/iss/exp). resource-api는 realm role로 인가까지 수행
→ 게이트웨이를 우회한 직접호출도 막는 이중 검증. (위험신호 IP·레이트·시각은
Gateway가 관측해 전달하고, PIP가 받아 위험점수로 산출.)
```

**요청 흐름:** Client가 Keycloak에 로그인 → JWT 발급 → Client가 JWT를 실어 요청 →
Gateway가 매 요청마다 JWT 검증 → PDP에 "이 사용자가 이 리소스에 접근 가능?" 질의 →
PDP가 PIP에서 **주체 속성 + 동적 위험점수**를 받아 정책 평가 →
허용이면 `resource-api`로 통과, 거부면 403. `resource-api`는 통과된 요청도 **JWT를 한 번 더
독립 검증하고 realm role로 인가**하며, 내부 신뢰헤더/ mTLS로 우회 직접호출까지 차단한다(이중 검증).

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

## 4. 차별화 — 지속검증 / 위험적응 인가

대부분의 데모는 로그인 시 1회 허용하면 끝이다. 여기서는 **세션이 살아있는 동안에도 위험이 바뀌면 접근을 회수**한다.

### 4.1 설명 가능한 동적 위험점수 (PIP)

`RiskEngine`이 신호를 **가중합**해 0~100 점수로 환산하고, 각 기여 요인을 함께 반환한다(설명 가능한 인가).

| 신호 | 의미 | 기본 가중치 |
|---|---|---|
| `baseline` | 주체 기본 신뢰도 (등록 사용자 낮음 / 미등록 높음) | 주체별 |
| `device-untrusted` | 관리되지 않는 단말 | 40 |
| `ip-change` | 직전 관측과 다른 출발지 IP (이동·탈취 신호) | 30 |
| `rate-burst` | 슬라이딩 윈도우 내 요청수가 임계 초과 (폭주·스크래핑) | 40 |
| `off-hours` | 업무시간 외 접근 | 15 |

가중치·임계는 전부 설정으로 빼, **코드 수정 없이 조건만 바꿔 ALLOW↔DENY를 뒤집어** 시연할 수 있다.

### 4.2 정책 결정 (PDP)

`PolicyEngine`은 **deny-overrides** 모델: ① 위험점수가 임계(`risk-threshold`, 기본 80) 이상이면 리소스 무관하게 DENY →
② `payroll`은 finance 부서 + 업무시간 + 신뢰 디바이스에서만 허용 → ③ 그 외 기본 허용.
DENY 사유에는 점수 기여 내역을 그대로 실어 **"왜 막혔는지"가 응답·로그로 설명**된다.

### 4.3 능동 캐시 무효화 = 지속검증의 구현 수단

게이트웨이는 PDP 왕복을 줄이려 결정을 짧게 캐싱한다. 단순 TTL만으로는 캐시된 ALLOW가 TTL 동안 위험 상승을 무시한다 —
지속검증의 정반대다. 그래서 캐시 일관성을 **핵심 메커니즘**으로 끌어올렸다:

- **위험적응 TTL** — 고위험 결정은 더 짧게 캐싱해 더 자주 재평가 (`ttl = f(riskScore)`).
- **레이트 밴드 트리거** — 요청 레이트가 "폭주" 밴드를 넘나드는 순간 캐시를 강제 바이패스해 즉시 재평가 유발.
- **epoch 키-아웃** — PDP 결정에 주체별 위험 `epoch`를 실어 게이트웨이가 학습; epoch가 오르면 옛 캐시 결정이 즉시 무효.

→ **결과:** 같은 토큰·같은 세션에서 새 IP나 폭주를 주입하면, **재로그인 없이** 다음 호출이 `ALLOW → DENY`로 전이한다.

### 4.4 다중 게이트웨이 fan-out (Redis pub/sub)

게이트웨이가 여러 대면, 위험을 유발하지 않은 노드는 옛 ALLOW를 TTL 동안 캐시 히트로 낼 수 있다.
이를 막기 위해 **권위자인 PIP가** epoch 상승 시 Redis 채널로 발행하고, **모든 게이트웨이가** 구독해 즉시 키-아웃한다.

- 기본 **OFF** (`ztg.fanout.enabled=false`) — 단일 노드/테스트는 Redis 없이 동작.
- at-most-once를 허용하는 근거: **TTL·lazy 학습이 백스톱**이라 한 번 놓쳐도 곧 수렴(가용성 우선, publish 실패는 삼킴).
- Kafka가 아닌 이유: 지속성·재생 요구가 낮고 규모상 오버킬.

---

## 5. 운영 품질 (관측성 · 부하검증 · mTLS)

- **관측성:** 각 서비스가 `/actuator/prometheus` 노출 → Prometheus 스크랩 → Grafana 대시보드.
  PDP 호출 지연은 히스토그램으로 발행해 p99 계산. **요청 추적 ID**(MDC)로 게이트웨이→PDP→PIP 로그를 같은 ID로 상관.
- **장애 안전:** PDP/PIP 호출 실패 시 **fail-close**(차단)를 기본값으로 의식적으로 선택. 라이브 fail-close 스모크 통과.
- **부하검증 (k6):** 결정 캐시 전후 백투백 비교(VUS=50, 현재 코드) — **처리량 +63%(9,010→14,681 rps), p99 −17%(12.7→10.5ms), fail 0%**. 핵심은 **신선도 장치(위험적응 TTL·레이트 밴드 강제 바이패스)를 넣고도** 정상 경로 캐시 히트율 **99.7%**(180초 측정 중 강제 바이패스 단 3회)를 유지 — 보안 강화가 정상 트래픽 성능을 거의 반납하지 않음을 데이터로 확인. "캐시로 성능을 얻되 신선도를 위해 필요한 만큼만 반납"하는 트레이드오프를 측정으로 정량화.
- **서비스간 mTLS:** 게이트웨이↔PDP↔PIP 내부 통신을 상호 TLS로 보호 (`compose-apps.yml`).

### 5.1 패킷레벨 관측 — mTLS를 "와이어에서" 입증

"mTLS 적용했다"를 헤더 한 줄로 주장하는 대신 **tcpdump로 실제 패킷을 떠서** 증명했다.

- 컨테이너 내부 mTLS는 호스트 tcpdump엔 안 잡힌다 → **pdp 컨테이너 netns에 사이드카**로 붙여 gw→pdp·pdp→pip를 한 지점에서 캡처.
- **CertificateRequest(handshake type 13)** — 단방향 TLS엔 없는 메시지 = mTLS의 결정적 증거. 서버 `CN=pdp`·클라 `CN=gateway` 인증서 교환까지 평문 확인.
- **함정 발견:** 기본 협상이 TLS 1.3이라 핸드셰이크가 암호화돼 인증서가 안 보였다 → 관측 구간만 1.2로 내려 입증(두 캡처 대비 = "1.3은 메타데이터까지 가린다").
- **zero-trust를 패킷으로:** 인증서 없는 우회 호출은 빈 Certificate → 서버 `fatal Alert`로 즉시 절단.

→ 한 장 요약: **[docs/packet-study/mtls-wire-study.md](docs/packet-study/mtls-wire-study.md)** (상세 재현·Q&A는 그 안에서 링크)

### 5.2 L4 트러블슈팅 — 장애를 "와이어에서" 진단

정책 경로(pdp↔pip)에 `tc netem`으로 지연 100ms·손실 5%를 주입하고, 증상을 패킷+지표로 짚었다.

- **증상의 국소화 = 진단의 본질:** 재전송이 netem 건 링크(8083)에만 **0→107**, 주입 안 한 8084는 **0** → 패킷만으로 문제 구간 격리. e2e p99는 **40배(39.5ms→1.56s)**.
- **측정은 vantage에 의존한다:** pip egress에 건 100ms가 캡처 지점(pdp) 기준 **한 방향엔 안 보이고 반대 방향에만** RTT로 드러난다 — 같은 장애도 보는 각도가 결과를 바꾼다.
- **재전송은 TCP지 TLS가 아니다:** mTLS는 L4 **위** 계층이라 L4 증상을 못 가린다 — payload만 암호문이고 TCP 동작은 평문으로 다 보인다.

→ 한 장 요약: **[docs/packet-study/l4-netem-study.md](docs/packet-study/l4-netem-study.md)** (재현·필터·검증맵은 그 안에서 링크)

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
| `smoke-d1.ps1` | **재로그인 없이 ALLOW→DENY** (새 IP·폭주 주입) |
| `smoke-d1-fanout.ps1` | 다중 GW Redis fan-out 무효화 |
| `smoke-mtls.ps1` | 서비스간 mTLS |
| `loadtest.js` (k6) | 캐시 before/after 처리량·p99 |

---

## 7. 검증

- **L2 단위:** 위험점수 가중합, 정책 결정(ALLOW/DENY), 캐시 epoch 키-아웃, fan-out 코덱 라운드트립.
- **L3 e2e:** 정상 호출 ALLOW → IP 변경/폭주 주입 → 다음 호출 DENY (재로그인 없이).
- 전체 회귀는 `./gradlew build` 한 방으로 막는다(검증 실패 = 빌드 실패).

```bash
./gradlew build           # 전체 회귀
./gradlew test            # 단위/슬라이스 테스트만
```

---

## 8. 설계 원칙

- **fail-close 기본값** — 보안 데모이므로 모호하면 차단을 택하고 이유를 기록한다.
- **조건의 설정화** — 위험 가중치·임계·업무시간을 전부 외부화해, 코드 수정 없이 결과를 뒤집어 보일 수 있다.
- **설명 가능한 인가** — 모든 DENY는 "왜"(기여 신호·점수)를 응답·로그에 남긴다.
- **점수는 PIP, 임계는 PDP** — 정보점과 결정점의 책임을 분리(정보 산출 vs 정책 적용).
