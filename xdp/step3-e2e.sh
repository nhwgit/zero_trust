#!/bin/bash
# Step 3 e2e: 판단(PIP) → 트래픽 제어(XDP) 캡스톤.
#   커널(XDP) 관측 → Go 에이전트 rate.l4 신호 → PIP가 ack에 enforcement(deny+TTL) 반환 →
#   에이전트가 커널 deny map에 기록 → 위험 소스 IP 패킷이 스택 진입 전 DROP →
#   TTL(=hold) 만료 후 자동 해제(에이전트 sweep) → 다시 통과. (root, docker mTLS 스택 위)
#
# Step 2와의 차이: Step 2는 제어 지점이 L7(게이트웨이 403 DENY)이었다. Step 3은 같은 판단을
# 커널로 내려 위험 IP를 아예 스택 밖에서 드랍한다 — alice는 403조차 못 받고 L4에서 끊긴다(000).
# 그게 "관측 지점 L7→L3/4 하강"에 이은 "제어 지점 L7 DENY→커널 드랍 하강" 서사의 완성이다.
#
# ⚠️ 데모 단순화: 플러드와 alice가 같은 호스트(172.18.0.1=도커 브리지 GW)에서 나가므로, 그 IP를
# 커널에서 막으면 alice의 정상 트래픽도 함께 끊긴다. 이는 "IP 단위 에지 차단"의 성질을 그대로 보여준다
# (세션 단위 인가와 축이 다름 — xdp-study.md에 명시). 실서비스라면 공격 IP와 정상 IP가 갈린다.
#
# 전제: docker mTLS 스택 기동 + pip 이미지에 enforcement ack 포함(up-mtls-docker.ps1 재빌드).
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak
XDP=$PROJ/xdp
OUT=$XDP/out/step3-e2e.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
WORK=/tmp/ztg-step3
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
    if [ "$FAIL" -eq 0 ] && [ "$RC" -eq 0 ]; then echo "== STEP3 DONE: PASS =="; else echo "== STEP3 DONE: FAIL =="; fi
}
trap cleanup EXIT

echo "== 0. precondition: 컨테이너 5종 + 헬스 =="
for c in ztg-gateway ztg-pdp ztg-pip ztg-resource-api ztg-keycloak; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "FAIL: $c not running — up-mtls-docker.ps1 먼저"; exit 1; }
done
wait_health() { # wait_health <이름> <url> <timeout_s>
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

echo "== 1. mTLS 클라이언트 PEM 추출 (pdp.p12 재사용) =="
CERTS=$PROJ/docker/certs
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nokeys -clcerts -out "$WORK/client.crt.pem" 2>/dev/null
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nocerts -nodes -out "$WORK/client.key.pem" 2>/dev/null
[ -s "$WORK/client.crt.pem" ] && [ -s "$WORK/client.key.pem" ] || { echo "FAIL: PEM 추출 실패"; exit 1; }
MTLS=(--cacert "$CERTS/ca.crt" --cert "$WORK/client.crt.pem" --key "$WORK/client.key.pem")

# 새 이미지가 ack에 enforcement를 싣는지 먼저 확인(구 이미지면 enforcement:null) — fail-fast.
ACK=$(curl -s "${MTLS[@]}" -X POST https://localhost:8083/pip/signals/rate-l4 \
     -H 'Content-Type: application/json' -d '{"sourceIp":"192.0.2.99","synsInWindow":1,"packetsInWindow":1,"windowSeconds":5}')
echo "  probe ack: $ACK"
echo "$ACK" | grep -q '"enforcement":{"action":"deny"' && echo "  PASS  ack에 enforcement(deny) 포함" \
    || { echo "  FAIL  ack에 enforcement 없음 — pip 이미지 재빌드 필요"; exit 1; }

echo "== 2. XDP(enforce) compile + ztg-gateway netns eth0 native attach =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$XDP/rate_enforce.c" -o /tmp/rate_enforce.o || exit 1
GW_PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
echo "gateway pid=$GW_PID ip=$GWIP"
nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_enforce.o sec xdp || exit 1
nsenter -t "$GW_PID" -n ip -d link show eth0 | grep -iE 'xdp' | head -2

echo "== 3. Go 에이전트 빌드 + 기동 (-enforce: PIP 지시를 deny map에 기록) =="
( cd "$XDP/agent" && go build -buildvcs=false -o "$WORK/agent" . ) || exit 1
"$WORK/agent" -pip-url https://localhost:8083 \
    -cert "$WORK/client.crt.pem" -key "$WORK/client.key.pem" -ca "$CERTS/ca.crt" \
    -interval 1s -window 5s -syn-threshold 20 -cooldown 10s -enforce > "$WORK/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || { echo "FAIL: agent 기동 실패"; cat "$WORK/agent.log"; exit 1; }
grep -q 'enforcement ON' "$WORK/agent.log" && echo "  PASS  agent enforcement 모드" || { echo "  FAIL  enforcement 모드 아님"; cat "$WORK/agent.log"; exit 1; }

echo "== 4. alice 토큰 + 속성 =="
TOKEN=$(curl -s -X POST http://localhost:8081/realms/ztg/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=ztg-api&client_secret=ztg-api-secret&username=alice&password=alice123' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
[ -n "$TOKEN" ] || { echo "FAIL: 토큰 발급 실패"; exit 1; }
curl -s -o /dev/null "${MTLS[@]}" -X PUT https://localhost:8083/pip/attributes/alice \
    -H 'Content-Type: application/json' -d '{"department":"finance","deviceTrusted":false,"riskScore":10}'

alice() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOKEN" "http://$GWIP:8080/api/hello"; }

echo "== 5. baseline: 정상 alice = 200 (아직 차단 없음) =="
alice > /dev/null
sleep 1
check "정상 alice -> 200" "$(alice)" "200"

echo "== 6. 토큰 없는 SYN 플러드 80발 → 에이전트가 임계 초과 신호 → PIP enforcement 지시 =="
FLOOD_PIDS=()
for i in $(seq 1 80); do curl -s -o /dev/null --max-time 2 "http://$GWIP:8080/api/hello" & FLOOD_PIDS+=($!); done
wait "${FLOOD_PIDS[@]}"
echo "flood done"

echo "== 7. 커널 deny map에 위험 IP 등록 확인 (폴링 최대 15s) =="
DENY_SEEN=0
for t in $(seq 1 15); do
    if "$BPFTOOL" map dump name deny_ips 2>/dev/null | grep -q .; then
        # 비어있지 않고 엔트리가 실제로 있으면(키가 잡히면) 통과
        N=$("$BPFTOOL" map dump name deny_ips -j 2>/dev/null | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null)
        [ "${N:-0}" -ge 1 ] && { DENY_SEEN=1; echo "  (${t}s 만에 deny map 등록, entries=$N)"; break; }
    fi
    sleep 1
done
check "deny map에 위험 IP 등록" "$DENY_SEEN" "1"
echo "-- deny map dump --"; "$BPFTOOL" map dump name deny_ips 2>/dev/null
grep -q 'ENFORCE deny' "$WORK/agent.log" && echo "  PASS  agent ENFORCE 로그 확인" || { echo "  FAIL  ENFORCE 로그 없음"; FAIL=1; }

echo "== 8. 커널 드랍 확인: 이제 alice는 403이 아니라 L4에서 끊긴다(000=timeout) =="
# 같은 소스 IP가 deny map에 있으므로 SYN부터 드랍 → 커넥션 미성립 → curl 000.
DROP_CODE=$(alice)
check "차단 중 alice -> 000 (커널 드랍, 403 아님)" "$DROP_CODE" "000"

echo "== 9. 드랍 카운터 증가 확인 (커널이 실제로 패킷을 버렸다는 증거) =="
DROPS=$("$BPFTOOL" map dump name deny_ips -j 2>/dev/null | python3 -c '
import sys, json
rows = json.load(sys.stdin)
tot = 0
for r in rows:
    f = r.get("formatted", r)
    v = f["value"]
    # value가 dict(BTF 해석본)면 drops 필드, 아니면 raw 바이트 배열의 뒤 8바이트
    if isinstance(v, dict):
        tot += int(v.get("drops", 0))
    else:
        b = bytes(int(x,16) for x in v)
        tot += int.from_bytes(b[8:16], "little")
print(tot)
' 2>/dev/null)
echo "  kernel drops=$DROPS"
[ "${DROPS:-0}" -ge 1 ] && echo "  PASS  커널 드랍 카운터 >=1" || { echo "  FAIL  드랍 카운터 0"; FAIL=1; }

echo "== 10. 가역성: TTL(hold 30s) 만료 후 에이전트 sweep → deny 해제 → 다시 200 (최대 60s) =="
ALLOW_CODE=""
for t in $(seq 1 60); do
    ALLOW_CODE=$(alice)
    [ "$ALLOW_CODE" = "200" ] && { echo "  (${t}s 만에 복귀)"; break; }
    sleep 1
done
check "TTL 만료 후 alice -> 200 (에지 차단 자동 해제)" "$ALLOW_CODE" "200"
grep -q 'RELEASE' "$WORK/agent.log" && echo "  PASS  agent RELEASE(sweep) 로그 확인" || echo "  (참고) RELEASE 로그 없음 — 커널 만료로 통과했으나 sweep 전일 수 있음"

exit $FAIL
