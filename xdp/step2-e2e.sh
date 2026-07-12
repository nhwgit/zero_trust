#!/bin/bash
# D3 Step 2 e2e: 커널(XDP) 관측 → Go 에이전트 rate.l4 신호 → PIP 재평가(epoch bump) →
#                재로그인 없는 ALLOW→DENY → hold 만료 후 ALLOW 복귀 (root, docker mTLS 스택 위)
#
# 시나리오: alice가 172.18.0.1(WSL 호스트=도커 브리지 GW)에서 정상 사용 중, 같은 호스트에서
# "토큰 없는 SYN 플러드"가 시작된다. 이 플러드는 401이라 게이트웨이 L7 레이트(주체별)에 안 잡힌다 —
# 커널(XDP)만 본다. 에이전트가 임계 초과를 PIP에 신호 → alice(lastSeenIp=그 IP) 재평가 →
# rate-l4 +40 → 점수 임계(80) 초과 → epoch bump → 캐시 무효화 → alice의 같은 토큰이 403.
# 플러드가 멎고 hold(30s)가 지나면 다시 200(위험적응 = 영구 차단 아님).
#
# 전제: docker mTLS 스택 기동(up-mtls-docker.ps1) + pip 이미지에 /pip/signals/rate-l4 포함.
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak
XDP=$PROJ/xdp
OUT=$XDP/out/step2-e2e.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
WORK=/tmp/ztg-step2
mkdir -p "$WORK"
FAIL=0
AGENT_PID=""
GW_PID=""

check() { # check <이름> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $2)"; else echo "  FAIL  $1 (got $2, want $3)"; FAIL=1; fi
}

cleanup() {
    RC=$?   # 조기 exit(||exit 1)도 실패로 잡는다 — FAIL 플래그와 종료코드 둘 다 성공이어야 PASS.
    echo "== cleanup: agent kill + XDP detach =="
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    [ -n "$GW_PID" ] && nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv off 2>/dev/null
    echo "-- agent log --"
    cat "$WORK/agent.log" 2>/dev/null
    if [ "$FAIL" -eq 0 ] && [ "$RC" -eq 0 ]; then echo "== STEP2 DONE: PASS =="; else echo "== STEP2 DONE: FAIL =="; fi
}
trap cleanup EXIT

echo "== 0. precondition: 컨테이너 5종 + PIP 신호 엔드포인트 =="
for c in ztg-gateway ztg-pdp ztg-pip ztg-resource-api ztg-keycloak; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "FAIL: $c not running — up-mtls-docker.ps1 먼저"; exit 1; }
done

# WSL 유휴 종료→콜드 스타트 시 restart 정책이 컨테이너를 새로 띄운다(부팅 ~20s). 관리 포트(평문)로
# pip/pdp/gateway가 실제 준비됐는지 확인한 뒤에야 mTLS를 때린다(안 그러면 핸드셰이크 SYSCALL).
wait_health() { # wait_health <이름> <url> <timeout_s>
    for _ in $(seq 1 "$3"); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$2")" = "200" ] && { echo "  UP  $1"; return 0; }
        sleep 1
    done
    echo "FAIL: $1 not healthy ($2)"; return 1
}
wait_health "pip(8093)"     http://localhost:8093/actuator/health 90 || exit 1
wait_health "pdp(8094)"     http://localhost:8094/actuator/health 90 || exit 1
wait_health "gateway(8080)" http://localhost:8080/actuator/health 90 || exit 1
wait_health "keycloak(8081)" http://localhost:8081/realms/ztg/.well-known/openid-configuration 90 || exit 1

echo "== 1. mTLS 클라이언트 PEM 추출 (pdp.p12 재사용 — PIP는 CA 서명 클라 인증서만 요구) =="
CERTS=$PROJ/docker/certs
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nokeys -clcerts -out "$WORK/client.crt.pem" 2>/dev/null
openssl pkcs12 -in "$CERTS/pdp.p12" -passin pass:ztg-mtls-pass -nocerts -nodes -out "$WORK/client.key.pem" 2>/dev/null
[ -s "$WORK/client.crt.pem" ] && [ -s "$WORK/client.key.pem" ] || { echo "FAIL: PEM 추출 실패"; exit 1; }
MTLS=(--cacert "$CERTS/ca.crt" --cert "$WORK/client.crt.pem" --key "$WORK/client.key.pem")

# 새 엔드포인트가 이미지에 있는지 먼저 확인(구 이미지면 404) — 미배포 상태로 플러드까지 가지 않게 fail-fast.
EP=$(curl -s -o /dev/null -w '%{http_code}' "${MTLS[@]}" -X POST https://localhost:8083/pip/signals/rate-l4 \
     -H 'Content-Type: application/json' -d '{"sourceIp":"192.0.2.99","synsInWindow":1,"packetsInWindow":1,"windowSeconds":5}')
check "PIP /pip/signals/rate-l4 존재(200)" "$EP" "200"
[ "$EP" != "200" ] && exit 1

echo "== 2. XDP compile + ztg-gateway netns eth0 native attach (step1 패턴) =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$XDP/rate_observe.c" -o /tmp/rate_observe.o || exit 1
GW_PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
echo "gateway pid=$GW_PID ip=$GWIP"
nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_observe.o sec xdp || exit 1
nsenter -t "$GW_PID" -n ip -d link show eth0 | grep -iE 'xdp' | head -2

echo "== 3. Go 에이전트 빌드 + 기동 (임계: 5s 창에 SYN 20 초과) =="
# -buildvcs=false: 소스가 git repo(프로젝트) 안이라 go가 VCS 스탬핑을 시도하다 실패한다(무관한 메타데이터).
( cd "$XDP/agent" && go build -buildvcs=false -o "$WORK/agent" . ) || exit 1
"$WORK/agent" -pip-url https://localhost:8083 \
    -cert "$WORK/client.crt.pem" -key "$WORK/client.key.pem" -ca "$CERTS/ca.crt" \
    -interval 1s -window 5s -syn-threshold 20 -cooldown 10s > "$WORK/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || { echo "FAIL: agent 기동 실패"; cat "$WORK/agent.log"; exit 1; }

echo "== 4. alice 토큰 발급(이후 재발급 없음 = 재로그인 없음) + 속성 세팅(score 50 = ALLOW 경계 아래) =="
TOKEN=$(curl -s -X POST http://localhost:8081/realms/ztg/protocol/openid-connect/token \
    -d 'grant_type=password&client_id=ztg-api&client_secret=ztg-api-secret&username=alice&password=alice123' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
[ -n "$TOKEN" ] || { echo "FAIL: 토큰 발급 실패"; exit 1; }
curl -s -o /dev/null "${MTLS[@]}" -X PUT https://localhost:8083/pip/attributes/alice \
    -H 'Content-Type: application/json' -d '{"department":"finance","deviceTrusted":false,"riskScore":10}'

alice() { # 컨테이너 IP로 직접 → 소스 IP가 XDP 관측 IP(172.18.0.1)와 동일. XFF 없음(소켓 주소가 신호).
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOKEN" "http://$GWIP:8080/api/hello"
}

echo "== 5. baseline: 정상 alice = ALLOW =="
alice > /dev/null   # warm-up: lastSeenIp/점수 기준 고정(재실행 잔존 상태 흡수)
sleep 1
check "정상 alice /api/hello -> 200 ALLOW" "$(alice)" "200"

echo "== 6. 토큰 없는 SYN 플러드 80발 (L7은 전부 401 — 주체 레이트에 안 잡힌다. XDP만 본다) =="
# ⚠️ 플러드 curl PID만 wait 한다 — bare `wait`는 백그라운드 에이전트(무한 실행)까지 기다려 영구 블록된다.
FLOOD_PIDS=()
for i in $(seq 1 80); do curl -s -o /dev/null --max-time 2 "http://$GWIP:8080/api/hello" & FLOOD_PIDS+=($!); done
wait "${FLOOD_PIDS[@]}"
echo "flood done"

echo "== 7. 커널 신호 → PIP 재평가 → 같은 토큰이 DENY로 전이 (폴링 최대 15s) =="
DENY_CODE=""
for t in $(seq 1 15); do
    DENY_CODE=$(alice)
    [ "$DENY_CODE" = "403" ] && { echo "  (${t}s 만에 전이)"; break; }
    sleep 1
done
check "플러드 후 alice /api/hello -> 403 DENY (재로그인 없이)" "$DENY_CODE" "403"
# 거부 사유에 커널 근거(rate-l4)가 실렸는지 — 설명 가능성 확인.
REASON=$(curl -s -D - -o /dev/null --max-time 5 -H "Authorization: Bearer $TOKEN" "http://$GWIP:8080/api/hello" \
    | grep -i '^X-Denied-Reason' | head -1)
echo "  deny reason: $REASON"
echo "$REASON" | grep -q 'rate-l4' && echo "  PASS  거부 사유에 rate-l4 포함" || { echo "  FAIL  거부 사유에 rate-l4 없음"; FAIL=1; }

echo "== 8. 에이전트가 실제로 신호를 쐈는지 (agent.log) =="
grep -q 'signal 172\.' "$WORK/agent.log" && echo "  PASS  agent -> PIP rate.l4 신호 발신 확인" \
    || { echo "  FAIL  agent 신호 로그 없음"; FAIL=1; }
grep -q '"reassessedSubjects":\["alice"\]' "$WORK/agent.log" && echo "  PASS  PIP ack에 alice 재평가 포함" \
    || echo "  (참고) ack에 alice 미포함 — agent.log 확인"

echo "== 9. 가역성: 플러드 멎고 hold(30s) 만료 후 다시 ALLOW (폴링 최대 50s) =="
ALLOW_CODE=""
for t in $(seq 1 50); do
    ALLOW_CODE=$(alice)
    [ "$ALLOW_CODE" = "200" ] && { echo "  (${t}s 만에 복귀)"; break; }
    sleep 1
done
check "hold 만료 후 alice /api/hello -> 200 ALLOW (복귀)" "$ALLOW_CODE" "200"

exit $FAIL
