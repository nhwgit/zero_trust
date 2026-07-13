#!/bin/bash
# D3 Step 4 (선택) — 상대 성능: "유저스페이스 처리 vs XDP 커널 드랍"의 게이트웨이 CPU before/after.
#
# 무엇을 재나: 토큰 없는 연결 플러드가 게이트웨이로 쏟아질 때, 그 패킷이
#   (A) 스택으로 올라가 유저스페이스가 처리(=Step 2식 L7 거부, 매 요청 TCP+HTTP+JWT 필터→401) 할 때와
#   (B) XDP가 스택 진입 전에 드랍(Step 3)할 때
# 게이트웨이 컨테이너의 CPU%가 어떻게 갈리는지를 같은 부하로 비교한다.
#
# 공정성 통제(핵심): 두 팔 모두 같은 rate_enforce.o를 attach한 상태로 측정한다. 유일한 차이는
#   deny map이 비었나(A: 전부 XDP_PASS) / 플러드 소스 IP가 박혀있나(B: 그 IP만 XDP_DROP)뿐.
#   즉 XDP 프로그램 자체의 상시 오버헤드는 양팔에 공통이고, 순수하게 "드랍의 효과"만 남는다.
#   (Step 3은 PIP→에이전트 경로로 deny를 채웠다. 여기선 그 탐지 지연을 배제하려 측정 창 전체를
#    deny 상태로 고정하려고 deny map에 직접 핀한다 — Phase 5의 "게이트웨이만 토글" 통제와 같은 결.)
#
# ⚠️ 측정 순서 = 커널드랍(B) 먼저, 유저스페이스(A) 나중. 이유: A는 20s에 수만 커넥션을 열어
#   호스트에 TIME_WAIT를 쌓는다 → 곧바로 B를 돌리면 클라이언트가 로컬 포트 고갈로 SYN조차 못 보내
#   "게이트웨이가 한가한 게 XDP 드랍 덕인지 클라 굶주림인지" 구분이 흐려진다. B를 먼저 깨끗한 상태에서
#   돌리고, B에서 실제로 커널이 드랍했음을 deny map drops>0으로 못박는다(측정 내 자기검증).
#
# ⚠️ 절대 성능은 범위 밖이다: WSL2 veth는 가상 데이터패스라 Mpps 같은 절대치는 의미 없다.
#   이 측정의 주장은 "같은 환경·같은 부하에서 커널 드랍이 유저스페이스 처리 대비 게이트웨이 CPU를
#   얼마나 덜어내나"라는 상대 델타뿐이다(Phase 5 +63%/−17%과 동일한 상대 비교 서사).
#
# ⚠️ 데모 단순화(Step 3과 동일): 플러드와 정상 트래픽이 같은 호스트 IP(172.18.0.1=도커 브리지 GW)에서
#   나가므로, 그 IP를 막으면 정상 트래픽도 함께 끊긴다 — IP 축 에지 차단의 성질(세션 축 인가와 다름).
#   그래서 "정상 사용자 처리량"은 이 데모로 깨끗이 측정할 수 없고, 지표를 게이트웨이 CPU로 한정한다.
#
# 전제: docker mTLS 스택 기동(up-mtls-docker.ps1). root 필요(XDP attach + bpftool).
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak
XDP=$PROJ/xdp
OUT=$XDP/out/step4-perf.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool
GW_PID=""
WORK=/tmp/ztg-step4
rm -rf "$WORK"; mkdir -p "$WORK"

# 측정 파라미터(짧게: WSL idle-shutdown 회피)
DURATION=20          # 각 팔의 플러드 지속(초)
WORKERS=24           # 동시 플러드 워커 수
SAMPLES=8            # 창 동안 CPU 샘플 횟수

cleanup() {
    echo "== cleanup: deny map 비우기 + XDP detach =="
    [ -n "$GW_PID" ] && "$BPFTOOL" map delete name deny_ips key hex "$KEYHEX" 2>/dev/null
    [ -n "$GW_PID" ] && nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv off 2>/dev/null
}
trap cleanup EXIT

echo "== 0. precondition: 컨테이너 + 게이트웨이 헬스 =="
for c in ztg-gateway ztg-pdp ztg-pip; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || { echo "FAIL: $c not running — up-mtls-docker.ps1 먼저"; exit 1; }
done
for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://localhost:8080/actuator/health)" = "200" ] && break
    sleep 1
done

echo "== 1. XDP(enforce) compile + ztg-gateway netns eth0 native attach =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$XDP/rate_enforce.c" -o /tmp/rate_enforce.o || exit 1
GW_PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
BRIDGE=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' ztg-gateway)
echo "gateway pid=$GW_PID container_ip=$GWIP flood_source(bridge)=$BRIDGE"
nsenter -t "$GW_PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_enforce.o sec xdp || exit 1
# 플러드 소스 IP(브리지 GW)를 deny map key 바이트로 변환(네트워크 바이트오더 = 도트 순서 그대로).
KEYHEX=$(printf '%02x %02x %02x %02x' ${BRIDGE//./ })
echo "deny map key(hex bytes) = $KEYHEX"

# 부하 생성기: WORKERS개 워커가 DURATION초 동안 게이트웨이로 연결 플러드. 각 워커는 처리한 요청 수를 기록.
flood() { # flood <arm_name>
    local arm=$1
    rm -f "$WORK"/w_*.cnt
    local pids=()
    local deadline=$(( $(date +%s) + DURATION ))
    for w in $(seq 1 "$WORKERS"); do
        (
            local n=0
            while [ "$(date +%s)" -lt "$deadline" ]; do
                curl -s -o /dev/null --connect-timeout 1 --max-time 2 "http://$GWIP:8080/api/hello" && n=$((n+1))
            done
            echo "$n" > "$WORK/w_${w}.cnt"
        ) &
        pids+=($!)
    done
    # 창 동안 게이트웨이 CPU 샘플(도커 stats --no-stream 각 호출 ~1s 소요).
    local sums="$WORK/${arm}.cpu"; : > "$sums"
    for _ in $(seq 1 "$SAMPLES"); do
        docker stats --no-stream --format '{{.CPUPerc}}' ztg-gateway 2>/dev/null | tr -d '%' >> "$sums"
    done
    wait "${pids[@]}" 2>/dev/null
    # 완료 요청 합계
    local total=0 c
    for f in "$WORK"/w_*.cnt; do read -r c < "$f"; total=$((total+c)); done
    echo "$total"
}

cpu_stat() { # cpu_stat <cpu_file>  -> "avg max"
    awk 'NR==1{mx=$1} {s+=$1; n++; if($1>mx)mx=$1} END{printf "%.1f %.1f", (n?s/n:0), mx}' "$1"
}

echo "== 2. idle baseline: 부하 없이 게이트웨이 CPU (참고선) =="
: > "$WORK/idle.cpu"
for _ in $(seq 1 4); do docker stats --no-stream --format '{{.CPUPerc}}' ztg-gateway 2>/dev/null | tr -d '%' >> "$WORK/idle.cpu"; done
IDLE=$(cpu_stat "$WORK/idle.cpu")
echo "  idle CPU avg/max = $IDLE %"

drops_total() { "$BPFTOOL" map dump name deny_ips -j 2>/dev/null | python3 -c '
import sys, json
tot = 0
for r in json.load(sys.stdin):
    f = r.get("formatted", r); v = f["value"]
    tot += int(v["drops"]) if isinstance(v, dict) else int.from_bytes(bytes(int(x,16) for x in v)[8:16], "little")
print(tot)
' 2>/dev/null; }

echo "== 3. ARM B (XDP 커널 드랍) — 먼저: 플러드 소스 IP를 deny map에 핀 → SYN부터 드랍 =="
# value = deny_entry{expires_at_ns(u64 LE), drops(u64 LE)} — 만료를 max로 둬 측정 창 내내 드랍.
"$BPFTOOL" map update name deny_ips key hex $KEYHEX \
    value hex ff ff ff ff ff ff ff ff 00 00 00 00 00 00 00 00 || { echo "FAIL: deny map 등록 실패"; exit 1; }
echo "  deny map 등록 확인:"; "$BPFTOOL" map dump name deny_ips
REQ_B=$(flood B)
B=$(cpu_stat "$WORK/B.cpu")
DROPS_B=$(drops_total)
echo "  ARM B gateway CPU avg/max = $B % | 완료된 플러드 요청 = $REQ_B | 커널 드랍 카운터 = $DROPS_B"
[ "${DROPS_B:-0}" -ge 1 ] && echo "  PASS  커널이 실제로 드랍(drops>0) → 게이트웨이 한가함은 XDP 드랍 덕" \
    || echo "  WARN  drops=0 — 클라이언트가 SYN을 못 보냈을 수 있음(측정 신뢰도 주의)"
"$BPFTOOL" map delete name deny_ips key hex $KEYHEX 2>/dev/null   # 해제(A는 유저스페이스가 처리해야)

echo "== 4. 포트 회수 대기(TIME_WAIT 소진) 후 ARM A =="
sleep 5

echo "== 5. ARM A (유저스페이스 처리): deny map 비움 → 플러드가 전부 스택으로(401) =="
REQ_A=$(flood A)
A=$(cpu_stat "$WORK/A.cpu")
echo "  ARM A gateway CPU avg/max = $A % | 완료된 플러드 요청 = $REQ_A (전부 유저스페이스가 처리)"

echo ""
echo "==================== 결과 요약 ===================="
printf "  idle(참고)          CPU avg/max = %s %%\n" "$IDLE"
printf "  ARM A 유저스페이스    CPU avg/max = %s %%   (플러드 401 처리 %s건)\n" "$A" "$REQ_A"
printf "  ARM B XDP 커널드랍    CPU avg/max = %s %%   (스택 도달 %s건)\n" "$B" "$REQ_B"
# 상대 델타(avg 기준)
A_AVG=${A%% *}; B_AVG=${B%% *}
awk -v a="$A_AVG" -v b="$B_AVG" 'BEGIN{
    if(a>0){ printf "  → XDP 드랍이 게이트웨이 CPU를 %.1f%%p(%.0f%% 상대) 덜어냄 (%s → %s)\n", a-b, (a-b)/a*100, a, b }
}'
echo "=================================================="
echo "== STEP4 DONE =="
