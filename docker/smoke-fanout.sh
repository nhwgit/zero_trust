#!/usr/bin/env bash
# fan-out 스모크 — 다중 게이트웨이 능동 무효화(Redis pub/sub)
#
# 무엇을 증명하나: 한 게이트웨이(GW1)에서 위험이 올라 PIP가 epoch를 bump하면,
# PIP가 Redis 채널로 publish하고 "위험을 유발하지 않은" GW2도 그 메시지를 받아 캐시를 즉시 키-아웃한다.
# 그래서 GW2는 자기 PDP 왕복(=옛 epoch 학습)을 기다리지 않고, TTL이 남았는데도 다음 요청부터 재평가한다 ->
# 같은 토큰·재로그인 없이 GW2의 ALLOW가 DENY로 전이한다. (fan-out이 없었다면 GW2는 TTL 동안 옛 ALLOW 유지.)
#
# 지렛대로 IP 변화(+30, PIP 전역 lastSeenIp)를 쓴다 — IP/epoch는 PIP가 전역으로 들고 있어
# fan-out 효과(노드 간 ALLOW->DENY)가 깨끗하게 드러난다.
#
# 추가로 step 4~5는 "레이트 관측 소유권"을 검증한다: fanout 모드에선 레이트 카운터가 노드-로컬이 아니라
# Redis 공유 집계다 — 폭주를 두 게이트웨이에 반씩 나눠 흘려도(각 노드 단독으론 임계 미달) 전역 합산이
# 임계를 넘어 폭주로 검출돼야 한다. (노드-로컬 카운터였다면 희석돼 영영 안 잡힌다.)
#
# 전제(모두 bootRun = 평문. PIP attribute PUT 때문에 평문 PIP가 필요. Redis만 컨테이너):
#   Redis(6379):   docker compose -f docker/docker-compose.yml -f docker/compose-fanout.yml up -d redis
#   Keycloak(8081): wsl bash docker/kc-hold.sh
#   resource-api(8082): ./gradlew :resource-api:bootRun
#   pdp(8084):     BUSINESS_HOUR_START=0 BUSINESS_HOUR_END=24 ./gradlew :pdp:bootRun
#   pip(8083):     FANOUT_ENABLED=true REDIS_HOST=localhost \
#                  ZTG_PIP_RISK_BUSINESS_HOUR_START=0 ZTG_PIP_RISK_BUSINESS_HOUR_END=24 ./gradlew :pip:bootRun
#   gateway(8080): FANOUT_ENABLED=true REDIS_HOST=localhost DECISION_CACHE_TTL=30s \
#                  DECISION_CACHE_HIGH_RISK_SCORE=70 RATE_WINDOW=30s ./gradlew :gateway:bootRun
#   gateway2(8090):SERVER_PORT=8090 + 위 gateway와 동일 env로 ./gradlew :gateway:bootRun
#   (Windows 호스트에서는 각 창에서 $env:이름='값' 후 .\gradlew.bat — 값은 위와 동일)
#
#   - TTL 30s + high-risk-score 70: GW2가 캐시한 home ALLOW(score 50<70)는 30초간 산다 -> fan-out이 없으면
#     스모크 내내 200이어야 한다. 그 30초 창 안에서 GW2가 403으로 뒤집히면 그건 TTL이 아니라 fan-out이다.
#   - 업무시간 0-24로 off-hours(+15)를 빼 점수를 결정적으로 둔다(이 스모크는 'fan-out'과 '레이트 소유권' 축만 본다).
#   - RATE_WINDOW 30s: step 5가 폭주 70건을 순차 HTTP로 보내는 동안 윈도우가 닫히지 않게 여유를 준다
#     (임계 60은 기본값 그대로 — PIP burst-threshold 60과의 정합 유지).
#
# 점수 산식(alice=finance+미신뢰, baseline 10, PDP 위험임계 80):
#   home IP        = baseline 10 + device 40            = 50  (< 80 => ALLOW)
#   다른(새) IP    = 10 + 40 + ip-change 30             = 80  (>= 80 => DENY)
set -u

GW1="${GW1:-http://localhost:8080}"
GW2="${GW2:-http://localhost:8090}"
PIP="${PIP:-http://localhost:8083}"
KC="${KC:-http://localhost:8081}"
HOME_IP="203.0.113.10"   # alice의 평소 출발지(PIP의 직전 관측 기준)
NEW_IP="198.51.100.66"   # GW1에서 위험을 올리는 낯선 출발지
pass=0; fail=0

token() {
  curl -s -X POST "$KC/realms/ztg/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=ztg-api -d client_secret=ztg-api-secret \
    -d "username=$1" -d "password=$2" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

code_from() {  # $1 url, $2 token, $3 ip
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer $2" -H "X-Forwarded-For: $3" "$1" || echo "-1"
}

set_attr() {  # $1 subject, $2 dept, $3 trusted(true|false), $4 risk
  curl -s -o /dev/null -X PUT "$PIP/pip/attributes/$1" -H 'Content-Type: application/json' \
    -d "{\"department\":\"$2\",\"deviceTrusted\":$3,\"riskScore\":$4}"
}

check() {  # $1 name, $2 got, $3 want
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $2)"; pass=$((pass+1));
  else echo "  FAIL  $1 (got $2, want $3)"; fail=$((fail+1)); fi
}

echo "== 토큰 발급 (이후 한 번도 재발급하지 않는다 = 재로그인 없음) =="
ALICE=$(token alice alice123)
[ -n "$ALICE" ] || { echo "토큰 발급 실패 — Keycloak($KC) 확인" >&2; exit 1; }
set_attr alice finance false 10   # 미신뢰 디바이스 -> home 50(ALLOW) / 새 IP 80(DENY)
# 리셋: 이전 실행이 남긴 위험 맥락(lastSeenIp·ip-change hold 30s)을 비운다(재실행 결정성). epoch는 보존돼
# 게이트웨이 단조 학습과 정합 — 리셋 후 첫 평가는 "첫 관측"이라 점수 50이 결정적으로 나온다.
curl -s -o /dev/null -X DELETE "$PIP/pip/risk/alice"

echo
echo "== 0) 두 게이트웨이 모두 home IP로 워밍업 -> 각자 ALLOW를 캐시 =="
# GW1 첫 요청: lastSeenIp=null(리셋 직후)이라 ip-change 없음 -> score 50 -> ALLOW, PIP가 lastSeenIp=home으로 고정.
code_from "$GW1/api/hello" "$ALICE" "$HOME_IP" >/dev/null
check "GW1 alice /api/hello (home IP) -> 200 ALLOW" "$(code_from "$GW1/api/hello" "$ALICE" "$HOME_IP")" 200
# GW2도 home으로 캐시를 채운다(별도 인스턴스라 캐시는 독립). PIP는 home==lastSeenIp라 점수/epoch 불변.
check "GW2 alice /api/hello (home IP) -> 200 ALLOW (GW2 캐시에 ALLOW 적재)" "$(code_from "$GW2/api/hello" "$ALICE" "$HOME_IP")" 200

echo
echo "== 1) GW1에서만 위험을 올린다: 새 IP -> ip-change(+30) -> score 80 -> DENY -> epoch bump =="
echo "   이 평가에서 PIP가 epoch를 0->1로 올리고 Redis 채널로 (alice,1)을 publish한다. PIP lastSeenIp:=new."
check "GW1 alice /api/hello (NEW IP) -> 403 DENY" "$(code_from "$GW1/api/hello" "$ALICE" "$NEW_IP")" 403

echo
echo "== 2) fan-out 전파 대기(짧게) — GW2가 (alice,1)을 받아 자기 캐시를 키-아웃한다 =="
sleep 0.8   # pub/sub은 거의 즉시지만 리스너 스레드 반영 여유. TTL 30s 안이라 'TTL 아님'이 보장된다.

echo
echo "== 3) 헤드라인: GW2는 새 IP를 본 적 없고 TTL(30s)도 안 지났지만 home 요청이 ALLOW->DENY로 전이 =="
echo "   GW2의 ALLOW@epoch0가 fan-out으로 키-아웃 -> 미스 -> 재평가. PIP lastSeenIp=new라 home도 ip-change(new->home)"
echo "   -> score 80 -> DENY. fan-out이 없었다면 GW2는 30s TTL 동안 옛 ALLOW를 그대로 200으로 냈을 것이다."
check "GW2 alice /api/hello (home IP) -> 403 DENY (재로그인 없이, 노드 간 전파)" "$(code_from "$GW2/api/hello" "$ALICE" "$HOME_IP")" 403

echo
echo "== 4) 레이트 소유권 준비: 위험 맥락 리셋 -> home으로 재워밍업(score 50 ALLOW) =="
# step 1~3이 남긴 ip-change hold(30s)·score 80을 비워 이번 축(레이트)만 남긴다. 이후 요청은 전부 home IP라
# ip-change 가중이 없고, 점수는 50(ALLOW)에서 시작한다. epoch는 보존돼 게이트웨이 단조 학습과 정합.
curl -s -o /dev/null -X DELETE "$PIP/pip/risk/alice"
check "GW1 재워밍업 (home IP) -> 200 ALLOW (score 50)" "$(code_from "$GW1/api/hello" "$ALICE" "$HOME_IP")" 200

echo
echo "== 5) 헤드라인2: 폭주 70건을 두 GW에 반씩(각 ~35건 < 임계 60) -> 전역 합산 70 > 60 -> DENY =="
echo "   레이트 카운터가 노드-로컬이었다면 어느 노드도 임계를 못 넘어(1/2 희석) 폭주가 안 잡힌다."
echo "   Redis 공유 집계가 전역 카운트를 만들고, 임계를 넘는 순간 밴드 전이 -> 강제 재평가 ->"
echo "   rate-burst(+40) -> score 90 -> DENY + epoch bump -> fan-out으로 두 노드 모두 즉시 차단."
for i in $(seq 0 69); do
  if [ $((i % 2)) -eq 0 ]; then gw="$GW1"; else gw="$GW2"; fi
  code_from "$gw/api/hello" "$ALICE" "$HOME_IP" >/dev/null
done
check "GW1 폭주 직후 (home IP) -> 403 DENY (전역 레이트 폭주 검출)" "$(code_from "$GW1/api/hello" "$ALICE" "$HOME_IP")" 403
check "GW2 폭주 직후 (home IP) -> 403 DENY (전역 레이트 폭주 검출)" "$(code_from "$GW2/api/hello" "$ALICE" "$HOME_IP")" 403

echo
echo "== 결과: $pass PASS / $fail FAIL =="
[ "$fail" -eq 0 ] || exit 1
