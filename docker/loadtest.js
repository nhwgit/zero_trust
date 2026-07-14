// k6 부하 스크립트 (게이트웨이 핫패스: /api/hello)
//
// 측정 대상: 게이트웨이 JWT 검증 → PDP 인가 질의 → 백엔드 전달의 전 구간 지연.
// 목적은 절대 성능이 아니라 결정 캐싱 도입 전/후 상대 비교다. 그래서 신뢰성 통제를 내장한다:
//   1) 토큰 만료 회피  — setup()에서 1회 발급해 전 VU 공유(런은 4분 이내로 유지).
//   2) 워밍업(JIT) 제외 — warmup 시나리오 구간 표본은 커스텀 지표(hot_*)에 넣지 않는다.
//   3) 경로 고정        — /api/hello(기본 허용·시간 무관)로 매 요청이 GW→PDP→백엔드를 일관되게 탄다.
//   (4) 요청당 INFO 로그는 기동 스크립트가 LOGGING_LEVEL_COM_ZTG=WARN으로 끈다 — up-loadtest.ps1)
//
// 실행(스모크):   k6 run docker\loadtest.js
// 실행(측정 예):  k6 run -e VUS=50 -e WARMUP=20s -e DURATION=180s docker\loadtest.js
//   주의: WARMUP+DURATION 합이 약 4분(accessTokenLifespan=300s)을 넘기지 말 것 → 넘으면 토큰 만료로 401 빠른경로(측정 무효).

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { Trend, Rate } from 'k6/metrics';

const KC     = __ENV.KC     || 'http://localhost:8081';
const GW     = __ENV.GW     || 'http://localhost:8080';
const PIP    = __ENV.PIP    || 'http://localhost:8083';
const REALM  = __ENV.REALM  || 'ztg';
const CLIENT = __ENV.CLIENT || 'ztg-api';
const SECRET = __ENV.SECRET || 'ztg-api-secret';
const USER   = __ENV.USER   || 'alice';
const PASS   = __ENV.PASS   || 'alice123';

const VUS      = parseInt(__ENV.VUS || '10', 10);
const WARMUP   = __ENV.WARMUP   || '15s';   // JIT/연결풀 준비 구간(버림)
const DURATION = __ENV.DURATION || '30s';   // 실제 측정 구간

// 측정 구간 표본만 담는 커스텀 지표(워밍업 제외). k6 summary에 p50/p90/p95/p99로 출력된다.
const hotLatency = new Trend('hot_req_duration', true);
const hotFailed  = new Rate('hot_req_failed');

export const options = {
  scenarios: {
    // 워밍업: 같은 부하를 먼저 흘려 JVM JIT/커넥션 풀을 데운다. 이 구간 표본은 버린다.
    warmup: {
      executor: 'constant-vus',
      vus: VUS,
      duration: WARMUP,
      exec: 'hit',
      tags: { phase: 'warmup' },
      gracefulStop: '2s',
    },
    // 측정: 워밍업 직후 시작. 이 구간만 hot_* 지표에 적재한다.
    measure: {
      executor: 'constant-vus',
      vus: VUS,
      startTime: WARMUP,
      duration: DURATION,
      exec: 'hit',
      tags: { phase: 'measure' },
      gracefulStop: '2s',
    },
  },
  thresholds: {
    // 스모크 기준(느슨). baseline/캐싱 비교에서는 숫자 자체보다 before/after 차이를 본다.
    hot_req_failed: ['rate<0.01'],
    hot_req_duration: ['p(95)<500', 'p(99)<1000'],
  },
};

export function setup() {
  // 1) PIP 속성 고정 — /api/hello가 항상 ALLOW 되도록 저위험·신뢰·정상부서로 세팅.
  const attrRes = http.put(
    `${PIP}/pip/attributes/${USER}`,
    JSON.stringify({ department: 'finance', deviceTrusted: true, riskScore: 10 }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  if (attrRes.status !== 200) {
    throw new Error(`PIP attribute setup failed: ${attrRes.status} ${attrRes.body}`);
  }

  // 2) 토큰 1회 발급 → 전 VU 공유(요청마다 재발급하지 않는다). 만료 통제는 런<4분으로.
  const tokRes = http.post(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
    grant_type: 'password',
    client_id: CLIENT,
    client_secret: SECRET,
    username: USER,
    password: PASS,
  });
  if (tokRes.status !== 200) {
    throw new Error(`token issuance failed: ${tokRes.status} ${tokRes.body}`);
  }
  const token = tokRes.json('access_token');
  console.log(`[setup] token acquired (len=${token.length}); PIP attrs fixed for ${USER}; VUS=${VUS} WARMUP=${WARMUP} DURATION=${DURATION}`);
  return { token };
}

export function hit(data) {
  const res = http.get(`${GW}/api/hello`, {
    headers: { Authorization: `Bearer ${data.token}` },
  });
  const ok = check(res, { 'status is 200': (r) => r.status === 200 });

  // 측정 구간 표본만 적재(워밍업 버림). 그 외(401/403)는 잘못된 ALLOW 전제를 뜻하므로 fail로 본다.
  if (exec.scenario.name === 'measure') {
    hotLatency.add(res.timings.duration);
    hotFailed.add(!ok);
  }
}
