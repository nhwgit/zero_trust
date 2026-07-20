#!/bin/bash
# 에지 차단 제외 대역 e2e: 신호 IP가 PIP_EDGE_BLOCK_EXEMPT(신뢰 프록시/LB 대역)에 들면
#   재평가·인가 회수(세션 축)는 그대로 수행하되 커널 드랍 지시(enforcement)만 생략된다.
#   공유 IP(LB)를 드랍하면 그 경유 사용자 전원이 끊기므로 — 잃는 것은 에지 최적화뿐.
#
# step3-e2e.sh와 같은 토폴로지에서 기대만 반전: deny map 비어 있고 alice는 000이 아니라 403.
# 전제: docker mTLS 스택 기동 + pip 컨테이너가 PIP_EDGE_BLOCK_EXEMPT=172.18.0.1로 떠 있을 것.
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak
XDP=$PROJ/xdp
OUT=$XDP/out/edge-exempt-e2e.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
WORK=/tmp/ztg-exempt
mkdir -p "$WORK"
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool
FAIL=0
AGENT_PID=""
GW_PID=""

check() { # check <이름> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $2)"; else echo "  FAIL  $1 (got $2, want $3)"; FAIL=1; fi
}

cleanup() {
    RC=$?
    echo "== cleanup: agent kill + XDP detach =="
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    [ -n "$GW_PID" ] && nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv off 2>/dev/null
    echo "-- agent log --"
    cat "$WORK/agent.log" 2>/dev/null
    if [ "$FAIL" -eq 0 ] && [ "$RC" -eq 0 ]; then echo "== EDGE-EXEMPT DONE: PASS =="; else echo "== EDGE-EXEMPT DONE: FAIL =="; fi
}
trap cleanup EXIT

echo "== 0. precondition: 컨테이너 5종 + 헬스 + pip 제외 대역 설정 =="
for c in ztg-gateway ztg-pdp ztg-pip ztg-resource-api ztg-keycloak; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "FAIL: $c not running — up-mtls-docker.ps1 먼저"; exit 1; }
done
docker inspect ztg-pip --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q '^PIP_EDGE_BLOCK_EXEMPT=172.18.0.0/16' \
    || { echo "FAIL: ztg-pip에 PIP_EDGE_BLOCK_EXEMPT=172.18.0.0/16 미설정 — 컨테이너 재기동 필요"; exit 1; }
wait_health() {
    for _ in $(seq 1 "$3"); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$2")" = "200" ] && { echo "  UP  $1"; return 0; }
        sleep 1
    done
    echo "FAIL: $1 not healthy ($2)"; return 1
}
wait_health "pip(8093)"      http://localhost:8093/actuator/health 90 || exit 1
wait_health "pdp(8094)"      http://localhost:8094/actuator/health 90 || exit 1
wait_health "gateway(8080)"  http://localhost:8080/actuator/health 90 || exit 1
wait_health "keycloak(8081)" http://localhost:8081/realms/ztg/.well-known/openid-configuration 90 || exit 1

echo "== 1. mTLS 클라이언트 PEM 추출 =="
CERTS=$PROJ/docker/certs
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nokeys -clcerts -out "$WORK/client.crt.pem" 2>/dev/null
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nocerts -nodes -out "$WORK/client.key.pem" 2>/dev/null
[ -s "$WORK/client.crt.pem" ] && [ -s "$WORK/client.key.pem" ] || { echo "FAIL: PEM 추출 실패"; exit 1; }
MTLS=(--cacert "$CERTS/ca.crt" --cert "$WORK/client.crt.pem" --key "$WORK/client.key.pem")

# 제외 대역 IP의 신호 → ack에 enforcement가 없어야 한다(핵심 계약, fail-fast).
# 프로브 IP는 alice의 네트워크 축(.1)과 겹치지 않게 별도 제외 IP(.99.99)를 쓴다 — 프로브가
# .1에 rate-l4 플래그를 심으면 baseline alice가 그 플래그를 물려받아 오염된다.
ACK=$(curl -s "${MTLS[@]}" -X POST https://localhost:8083/pip/signals/rate-l4 \
     -H 'Content-Type: application/json' -d '{"sourceIp":"172.18.99.99","synsInWindow":1,"packetsInWindow":1,"windowSeconds":5}')
echo "  probe ack: $ACK"
echo "$ACK" | grep -q '"enforcement":{"action":"deny"' \
    && { echo "  FAIL  제외 대역인데 ack에 deny enforcement가 실림"; exit 1; } \
    || echo "  PASS  제외 대역 신호의 ack에 enforcement 없음"

echo "== 2. XDP(enforce) attach + 에이전트(-enforce) 기동 =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$XDP/rate_enforce.c" -o /tmp/rate_enforce.o || exit 1
GW_PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
echo "gateway pid=$GW_PID ip=$GWIP"
nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_enforce.o sec xdp || exit 1
( cd "$XDP/agent" && go build -buildvcs=false -o "$WORK/agent" . ) || exit 1
"$WORK/agent" -pip-url https://localhost:8083 \
    -cert "$WORK/client.crt.pem" -key "$WORK/client.key.pem" -ca "$CERTS/ca.crt" \
    -interval 1s -window 5s -syn-threshold 20 -cooldown 10s -enforce > "$WORK/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || { echo "FAIL: agent 기동 실패"; cat "$WORK/agent.log"; exit 1; }

echo "== 3. alice 토큰 + 속성(score 50 = ALLOW 경계 아래) =="
TOKEN=$(curl -s -X POST http://localhost:8081/realms/ztg/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=ztg-api&client_secret=ztg-api-secret&username=alice&password=alice123' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
[ -n "$TOKEN" ] || { echo "FAIL: 토큰 발급 실패"; exit 1; }
curl -s -o /dev/null "${MTLS[@]}" -X PUT https://localhost:8083/pip/attributes/alice \
    -H 'Content-Type: application/json' -d '{"department":"finance","deviceTrusted":false,"riskScore":10}'
curl -s -o /dev/null "${MTLS[@]}" -X DELETE https://localhost:8083/pip/risk/alice

alice() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOKEN" "http://$GWIP:8080/api/hello"; }

echo "== 4. baseline: 정상 alice = 200 =="
alice > /dev/null
sleep 1
check "정상 alice -> 200" "$(alice)" "200"

echo "== 5. 토큰 없는 SYN 플러드 80발 (신호 IP=172.18.0.1 = 제외 대역) =="
FLOOD_PIDS=()
for i in $(seq 1 80); do curl -s -o /dev/null --max-time 2 "http://$GWIP:8080/api/hello" & FLOOD_PIDS+=($!); done
wait "${FLOOD_PIDS[@]}"
echo "flood done"

echo "== 6. 세션 축은 살아 있다: 재평가로 alice가 403 (000 아님 = 커널 드랍 없음) =="
DENY_CODE=""
for t in $(seq 1 15); do
    DENY_CODE=$(alice)
    [ "$DENY_CODE" = "403" ] && { echo "  (${t}s 만에 전이)"; break; }
    [ "$DENY_CODE" = "000" ] && break
    sleep 1
done
check "플러드 후 alice -> 403 (L7 인가 회수, 커널 드랍 아님)" "$DENY_CODE" "403"

echo "== 7. 에지 축은 생략됐다: deny map 비어 있음 + ENFORCE 로그 없음 =="
N=$("$BPFTOOL" map dump name deny_ips -j 2>/dev/null | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null)
check "deny map 엔트리 0" "${N:-0}" "0"
grep -q 'ENFORCE deny' "$WORK/agent.log" && { echo "  FAIL  ENFORCE 로그 존재(드랍 지시가 나갔다)"; FAIL=1; } \
    || echo "  PASS  agent ENFORCE 로그 없음"
if grep -q 'signal 172\.' "$WORK/agent.log"; then
    echo "  PASS  agent -> PIP 신호는 발신됨(관측은 정상)"
else
    echo "  FAIL  agent 신호 로그 없음 — src_ip_stats 덤프:"
    "$BPFTOOL" map dump name src_ip_stats 2>/dev/null | head -10
    FAIL=1
fi

exit $FAIL
