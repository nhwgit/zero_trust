#!/usr/bin/env bash
# fan-out 무효화 전파 지연 측정 — "위험 감지 -> 다른 게이트웨이가 차단하기까지 몇 ms인가"
#
# 무엇을 재나 (라운드마다):
#   GW1에 낯선 IP 요청(t0) -> PIP ip-change(+30) -> score 80 DENY + epoch bump + Redis publish(t1≈GW1 403 수신)
#   -> GW2를 home IP로 고속 폴링 -> 첫 403 관측(t2).
#   · revoke  = t2-t0 : 위험 트리거 발사부터 "다른" GW에서 차단이 보이기까지 (사용자 관점 회수 시간)
#   · fanout  = t2-t1 : GW1 DENY 확정(publish 완료 하한) 이후 GW2 집행까지 (전파+키아웃+재평가)
#   측정 해상도는 폴링 1회 왕복(수 ms)이라 fanout 수치는 상한(관측값 <= 실제 + 폴링 1회)이다.
#
# 전제: smoke-fanout.sh와 같은 토폴로지(Redis + KC + 호스트 JVM 5개). 단 폴링이 레이트 폭주로
# 오검출되지 않게 레이트 임계만 크게 연다(이 측정은 'ip-change -> 전파' 축만 본다):
#   gateway/gateway2: FANOUT_ENABLED=true REDIS_HOST=localhost DECISION_CACHE_TTL=30s \
#                     DECISION_CACHE_HIGH_RISK_SCORE=70 RATE_BURST_THRESHOLD=100000
#                     (+ WSL에서 쏘면 소켓 피어가 WSL IP라 XFF가 불신·무시된다(H2 설계) —
#                      GATEWAY_TRUSTED_PROXIES='127.0.0.0/8,::1/128,172.16.0.0/12'로 WSL 대역을 신뢰 목록에 추가)
#   pip:              FANOUT_ENABLED=true REDIS_HOST=localhost ZTG_PIP_RISK_BURST_THRESHOLD=100000 \
#                     ZTG_PIP_RISK_BUSINESS_HOUR_START=0 ZTG_PIP_RISK_BUSINESS_HOUR_END=24
#   pdp:              BUSINESS_HOUR_START=0 BUSINESS_HOUR_END=24
#
# 실행 위치: WSL 안에서 실행 권장(프로세스 fork가 빨라 폴링 해상도가 좋다). WSL -> Windows 호스트 JVM은
# localhost가 아니라 기본 라우트 게이트웨이 IP로 닿는다 — 미지정 시 자동 발견한다.
# 부하 중 측정: 별도 창에서 k6를 다른 주체(bob)로 흘린 채 그대로 실행한다(측정 주체 alice와 분리):
#   k6 run -e USER=bob -e PASS=bob123 -e VUS=50 -e WARMUP=15s -e DURATION=300s docker/loadtest.js
set -u

if [ -z "${GW1:-}" ] && grep -qi microsoft /proc/version 2>/dev/null; then
  HOST_IP=$(ip route show default | awk '/default/ {print $3; exit}')
  GW1="http://$HOST_IP:8080"; GW2="http://$HOST_IP:8090"
  PIP="http://$HOST_IP:8083"
  # KC는 WSL 안 컨테이너라 WSL 기준 localhost 그대로(호스트 IP로는 되돌아오지 않는다)
  echo "# WSL 감지: Windows 호스트 = $HOST_IP"
fi
GW1="${GW1:-http://localhost:8080}"
GW2="${GW2:-http://localhost:8090}"
PIP="${PIP:-http://localhost:8083}"
KC="${KC:-http://localhost:8081}"
ROUNDS="${ROUNDS:-30}"
HOME_IP="203.0.113.10"
NEW_IP="198.51.100.66"

now_ms() { date +%s%3N; }

token() {
  curl -s -X POST "$KC/realms/ztg/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=ztg-api -d client_secret=ztg-api-secret \
    -d "username=$1" -d "password=$2" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

code_from() {  # $1 url, $2 ip
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "Authorization: Bearer $ALICE" -H "X-Forwarded-For: $2" "$1" || echo "-1"
}

pctl() {  # $1 정렬된 공백구분 목록, $2 백분위(0-100) — 최근접 순위법
  local -a a=($1); local n=${#a[@]}
  local idx=$(( (n * $2 + 99) / 100 - 1 ))
  [ $idx -lt 0 ] && idx=0; [ $idx -ge $n ] && idx=$((n - 1))
  echo "${a[$idx]}"
}

ALICE=$(token alice alice123)
[ -n "$ALICE" ] || { echo "토큰 발급 실패 — Keycloak($KC) 확인" >&2; exit 1; }
curl -s -o /dev/null -X PUT "$PIP/pip/attributes/alice" -H 'Content-Type: application/json' \
  -d '{"department":"finance","deviceTrusted":false,"riskScore":10}'

revokes=""; fanouts=""; ok=0; bad=0
echo "round,revoke_ms,fanout_ms"
for r in $(seq 1 "$ROUNDS"); do
  # 토큰 수명(5분) 보호: 라운드가 길어지면 재발급(측정 축은 전파 지연이라 무관)
  if [ $((r % 20)) -eq 0 ]; then ALICE=$(token alice alice123); fi
  curl -s -o /dev/null -X DELETE "$PIP/pip/risk/alice"           # 위험 맥락 리셋(epoch 보존)
  w1=$(code_from "$GW1/api/hello" "$HOME_IP")                    # lastSeenIp:=home 고정
  w2=$(code_from "$GW2/api/hello" "$HOME_IP")                    # GW2 캐시에 ALLOW 적재
  if [ "$w1" != "200" ] || [ "$w2" != "200" ]; then
    echo "$r,SKIP(warm $w1/$w2),"; bad=$((bad+1)); sleep 1.2; continue
  fi
  t0=$(now_ms)
  trig=$(code_from "$GW1/api/hello" "$NEW_IP")                   # 트리거: DENY + bump + publish
  t1=$(now_ms)
  if [ "$trig" != "403" ]; then
    echo "$r,SKIP(trigger $trig),"; bad=$((bad+1)); sleep 1.2; continue
  fi
  t2=""; deadline=$((t1 + 5000))
  while :; do
    c=$(code_from "$GW2/api/hello" "$HOME_IP")
    now=$(now_ms)
    if [ "$c" = "403" ]; then t2=$now; break; fi
    if [ "$now" -gt "$deadline" ]; then break; fi
  done
  if [ -z "$t2" ]; then
    echo "$r,TIMEOUT,"; bad=$((bad+1)); sleep 1.2; continue
  fi
  revoke=$((t2 - t0)); fanout=$((t2 - t1))
  revokes="$revokes $revoke"; fanouts="$fanouts $fanout"; ok=$((ok+1))
  echo "$r,$revoke,$fanout"
  sleep 1.2   # 고위험 TTL(1s) 소진 + 다음 라운드 리셋 안정화
done

echo
echo "== 유효 $ok / 실패·스킵 $bad (rounds=$ROUNDS) =="
[ "$ok" -gt 0 ] || exit 1
rs=$(echo "$revokes" | tr ' ' '\n' | sed '/^$/d' | sort -n | tr '\n' ' ')
fs=$(echo "$fanouts" | tr ' ' '\n' | sed '/^$/d' | sort -n | tr '\n' ' ')
echo "revoke(트리거->타 GW 차단) ms: min=$(pctl "$rs" 0) p50=$(pctl "$rs" 50) p95=$(pctl "$rs" 95) max=$(pctl "$rs" 100)"
echo "fanout(GW1 DENY->GW2 차단) ms: min=$(pctl "$fs" 0) p50=$(pctl "$fs" 50) p95=$(pctl "$fs" 95) max=$(pctl "$fs" 100)"
