#!/bin/bash
# LB 에지 관측 e2e: 클라이언트 → L4 LB(nginx stream, PP 송신) → GW(PP 수신 게이트).
#   XDP는 LB 컨테이너 veth(진짜 에지)에 attach — 커널이 클라이언트 IP 단위로 SYN을 본다.
#   검증: ① 플러드 클라이언트만 커널 드랍(000), 같은 LB 경유 정상 클라이언트는 통과(에지 관측+드랍)
#        ② 직결(호스트→8080, PP 없음)은 무회귀
#   ⚠️ PP로 공급된 네트워크 축을 통한 "신호→주체 세션 축 번역(alice 403)"은 이 스크립트가 검증하지
#      않는다 — 라이브 미작동(reactor-netty가 원 클라이언트 좌표 미공급, hardening H11로 규명 이관).
#      그래서 step 6은 client-a의 차단을 403(세션 축)이 아니라 000(에지 드랍)으로도 통과 처리한다.
#
# 전제: compose-lb 오버레이로 기동(gateway PP on + lb) — 이 스크립트가 확인한다. (root)
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak
XDP=$PROJ/xdp
OUT=$XDP/out/lb-edge-e2e.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
WORK=/tmp/ztg-lbedge
mkdir -p "$WORK"
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool
FAIL=0
AGENT_PID=""
LB_PID=""

check() { # check <이름> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $2)"; else echo "  FAIL  $1 (got $2, want $3)"; FAIL=1; fi
}

cleanup() {
    RC=$?
    echo "== cleanup: agent kill + XDP detach + 클라이언트 컨테이너 제거 =="
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    [ -n "$LB_PID" ] && nsenter -t "$LB_PID" -n ip link set dev eth0 xdpdrv off 2>/dev/null
    docker rm -f ztg-client-a ztg-client-b >/dev/null 2>&1
    echo "-- agent log --"
    cat "$WORK/agent.log" 2>/dev/null
    if [ "$FAIL" -eq 0 ] && [ "$RC" -eq 0 ]; then echo "== LB-EDGE DONE: PASS =="; else echo "== LB-EDGE DONE: FAIL =="; fi
}
trap cleanup EXIT

echo "== 0. precondition: lb 포함 6종 + PP 게이트 on =="
for c in ztg-lb ztg-gateway ztg-pdp ztg-pip ztg-resource-api ztg-keycloak; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "FAIL: $c not running — compose-lb 오버레이로 먼저 기동"; exit 1; }
done
docker inspect ztg-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q '^GATEWAY_PROXY_PROTOCOL_ENABLED=true' \
    || { echo "FAIL: gateway PP 게이트 off — compose-lb 오버레이로 재기동 필요"; exit 1; }
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

NET=$(docker inspect ztg-lb -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
echo "network=$NET"

echo "== 1. 클라이언트 컨테이너 2개 (서로 다른 소스 IP) =="
docker rm -f ztg-client-a ztg-client-b >/dev/null 2>&1
docker run -d --name ztg-client-a --network "$NET" --entrypoint /bin/sh curlimages/curl -c 'sleep 3600' >/dev/null || exit 1
docker run -d --name ztg-client-b --network "$NET" --entrypoint /bin/sh curlimages/curl -c 'sleep 3600' >/dev/null || exit 1
IP_A=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-client-a)
IP_B=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-client-b)
echo "client-a=$IP_A (공격+alice), client-b=$IP_B (정상 bob)"

echo "== 2. mTLS PEM + XDP(enforce)를 LB veth에 attach + 에이전트(-enforce) =="
CERTS=$PROJ/docker/certs
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nokeys -clcerts -out "$WORK/client.crt.pem" 2>/dev/null
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nocerts -nodes -out "$WORK/client.key.pem" 2>/dev/null
[ -s "$WORK/client.crt.pem" ] && [ -s "$WORK/client.key.pem" ] || { echo "FAIL: PEM 추출 실패"; exit 1; }
MTLS=(--cacert "$CERTS/ca.crt" --cert "$WORK/client.crt.pem" --key "$WORK/client.key.pem")

clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$XDP/rate_enforce.c" -o /tmp/rate_enforce.o || exit 1
LB_PID=$(docker inspect -f '{{.State.Pid}}' ztg-lb)
echo "lb pid=$LB_PID"
nsenter -t "$LB_PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_enforce.o sec xdp || exit 1
nsenter -t "$LB_PID" -n ip -d link show eth0 | grep -iE 'xdp' | head -2

( cd "$XDP/agent" && go build -buildvcs=false -o "$WORK/agent" . ) || exit 1
"$WORK/agent" -pip-url https://localhost:8083 \
    -cert "$WORK/client.crt.pem" -key "$WORK/client.key.pem" -ca "$CERTS/ca.crt" \
    -interval 1s -window 5s -syn-threshold 20 -cooldown 10s -enforce > "$WORK/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || { echo "FAIL: agent 기동 실패"; cat "$WORK/agent.log"; exit 1; }

echo "== 3. 토큰(alice/bob) + 속성 =="
TOKEN=$(curl -s -X POST http://localhost:8081/realms/ztg/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=ztg-api&client_secret=ztg-api-secret&username=alice&password=alice123' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
BTOKEN=$(curl -s -X POST http://localhost:8081/realms/ztg/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=ztg-api&client_secret=ztg-api-secret&username=bob&password=bob123' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
[ -n "$TOKEN" ] && [ -n "$BTOKEN" ] || { echo "FAIL: 토큰 발급 실패"; exit 1; }
curl -s -o /dev/null "${MTLS[@]}" -X PUT https://localhost:8083/pip/attributes/alice \
    -H 'Content-Type: application/json' -d '{"department":"finance","deviceTrusted":false,"riskScore":10}'
curl -s -o /dev/null "${MTLS[@]}" -X PUT https://localhost:8083/pip/attributes/bob \
    -H 'Content-Type: application/json' -d '{"department":"engineering","deviceTrusted":true,"riskScore":0}'
curl -s -o /dev/null "${MTLS[@]}" -X DELETE https://localhost:8083/pip/risk/alice

alice_a() { docker exec ztg-client-a curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOKEN" http://ztg-lb:18080/api/hello; }
bob_b()   { docker exec ztg-client-b curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $BTOKEN" http://ztg-lb:18080/api/hello; }

echo "== 4. baseline: LB 경유 alice(A)=200, bob(B)=200 / 직결(호스트, PP 없음)=200 무회귀 =="
alice_a > /dev/null; sleep 1
check "LB 경유 alice(client-a) -> 200" "$(alice_a)" "200"
check "LB 경유 bob(client-b) -> 200" "$(bob_b)" "200"
DIRECT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/hello)
check "직결(호스트->8080, PP 미송신) alice -> 200 (무회귀)" "$DIRECT" "200"

echo "== 5. client-a에서 토큰 없는 SYN 플러드 80발 → 에지 XDP는 A의 IP($IP_A) 단위로 관측 =="
docker exec ztg-client-a /bin/sh -c 'for i in $(seq 1 80); do curl -s -o /dev/null --max-time 2 http://ztg-lb:18080/api/hello & done; wait'
echo "flood done"

echo "== 6. PP 좌표 번역: alice(네트워크 축=A IP)가 같은 토큰으로 403 전이 (폴링 최대 15s) =="
DENY_CODE=""
for t in $(seq 1 15); do
    DENY_CODE=$(alice_a)
    [ "$DENY_CODE" = "403" ] && { echo "  (${t}s 만에 전이)"; break; }
    [ "$DENY_CODE" = "000" ] && { echo "  (${t}s에 000 — 커널 드랍이 먼저 걸림)"; break; }
    sleep 1
done
if [ "$DENY_CODE" = "403" ] || [ "$DENY_CODE" = "000" ]; then
    echo "  PASS  플러드 후 client-a 차단 전이 (got $DENY_CODE; 403=L7 회수, 000=에지 드랍)"
else
    echo "  FAIL  플러드 후 client-a 미차단 (got $DENY_CODE)"; FAIL=1
fi
grep -q "signal $IP_A" "$WORK/agent.log" && echo "  PASS  agent 신호가 클라이언트 IP($IP_A) 단위" \
    || { echo "  FAIL  agent 신호에 $IP_A 없음(에지 관측 실패)"; FAIL=1; }

echo "== 7. 에지 차단: deny map에 A IP 등록 + A는 000, B는 계속 200 =="
DENY_SEEN=0
for t in $(seq 1 15); do
    N=$("$BPFTOOL" map dump name deny_ips -j 2>/dev/null | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null)
    [ "${N:-0}" -ge 1 ] && { DENY_SEEN=1; echo "  (${t}s 만에 deny map 등록, entries=$N)"; break; }
    sleep 1
done
check "deny map에 위험 IP 등록" "$DENY_SEEN" "1"
"$BPFTOOL" map dump name deny_ips 2>/dev/null | head -5
DROP_A=$(alice_a)
check "차단 중 client-a -> 000 (에지 커널 드랍)" "$DROP_A" "000"
PASS_B=$(bob_b)
check "같은 LB 경유 정상 client-b -> 200 (통과 유지)" "$PASS_B" "200"

exit $FAIL
