#!/bin/bash
# Step 1: rate_observe.c 컴파일 → ztg-gateway 컨테이너 netns eth0에 native attach →
#            트래픽 생성(ping + curl 연발) → src_ip_stats map으로 per-source-IP pkts/syns 확인 → detach (root)
# Step 0 결론 재사용: ingress 관측은 컨테이너 안 eth0. mount ns는 유지되므로 obj 경로는 호스트 경로 그대로.
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/xdp
OUT=$PROJ/out/step1-observe.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool
FAIL=0

echo "== 0. precondition: ztg-gateway 컨테이너 확인 =="
docker ps --format '{{.Names}} {{.Status}}' | grep ztg-gateway || { echo "FAIL: ztg-gateway not running — docker compose -f docker-compose.yml -f compose-apps.yml up -d 먼저"; exit 1; }

echo "== 1. compile =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$PROJ/rate_observe.c" -o /tmp/rate_observe.o
echo "compile rc=$?"
[ -f /tmp/rate_observe.o ] || exit 1

echo "== 2. resolve ztg-gateway netns/IP (컨테이너 재생성마다 바뀌므로 매번 해석) =="
PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
echo "pid=$PID gwip=$GWIP"

echo "== 3. native attach: 컨테이너 netns eth0 (ingress 관측 지점) =="
nsenter -t "$PID" -n ip link set dev eth0 xdpdrv obj /tmp/rate_observe.o sec xdp
RC=$?
echo "attach rc=$RC"
[ "$RC" -ne 0 ] && exit 1
nsenter -t "$PID" -n ip -d link show eth0 | grep -iE 'xdp|prog'

echo "== 4. traffic: ping 5회(ICMP=pkts만) + curl 20회(각각 새 TCP 연결=SYN 1개씩) =="
ping -c 5 -W 1 "$GWIP" | tail -1
CURL_OK=0
for i in $(seq 1 20); do
    # 토큰 없는 요청 → L7은 401이지만 무관: XDP는 L4 SYN을 이미 셌고, 응답이 오면 XDP_PASS(비차단)도 함께 증명된다.
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$GWIP:8080/api/hello")
    [ -n "$CODE" ] && [ "$CODE" != "000" ] && CURL_OK=$((CURL_OK+1))
done
echo "curl responses received: $CURL_OK/20 (XDP_PASS 증명 — 관측만 하고 차단하지 않음)"
MYIP=$(ip -o -4 addr show | awk -v gw="$GWIP" 'BEGIN{split(gw,a,".")} $4 ~ a[1]"."a[2] {sub(/\/.*/,"",$4); print $4; exit}')
echo "traffic source ip (docker bridge gateway) = $MYIP"

echo "== 5. map dump (BTF 덕에 구조체 필드명으로 보임) =="
"$BPFTOOL" map dump name src_ip_stats

echo "== 5b. 사람용 표: saddr → dotted IP, pkts/syns =="
"$BPFTOOL" map dump name src_ip_stats -j | python3 -c '
import sys, json, socket, struct
# bpftool -j는 BTF가 있으면 raw 바이트 배열 + "formatted"(타입 해석본)를 함께 준다 → formatted 우선, 둘 다 대응
def norm(r):
    f = r.get("formatted", r)
    k = f["key"]
    if isinstance(k, list):
        k = int.from_bytes(bytes(int(x, 16) for x in k), "little")
    return k, f["value"]
rows = json.load(sys.stdin)
print("%-16s%8s%8s" % ("src_ip", "pkts", "syns"))
for r in rows:
    k, v = norm(r)
    # saddr는 network byte order로 저장했고 정수화는 LE → 되돌려 패킹
    ip = socket.inet_ntoa(struct.pack("<I", k))
    print("%-16s%8d%8d" % (ip, v["pkts"], v["syns"]))
'

echo "== 6. 검증: 우리 소스 IP의 syns >= 20, pkts > syns =="
"$BPFTOOL" map dump name src_ip_stats -j | python3 -c "
import sys, json, socket, struct
def norm(r):
    f = r.get('formatted', r)
    k = f['key']
    if isinstance(k, list):
        k = int.from_bytes(bytes(int(x, 16) for x in k), 'little')
    return k, f['value']
rows = json.load(sys.stdin)
me = '$MYIP'
for r in rows:
    k, v = norm(r)
    ip = socket.inet_ntoa(struct.pack('<I', k))
    if ip == me:
        p, s = v['pkts'], v['syns']
        ok = s >= 20 and p > s
        print('%s: pkts=%d syns=%d -> %s' % (ip, p, s, 'PASS' if ok else 'FAIL'))
        sys.exit(0 if ok else 1)
print('FAIL: %s not found in map' % me)
sys.exit(1)
"
[ $? -ne 0 ] && FAIL=1

echo "== 7. detach =="
nsenter -t "$PID" -n ip link set dev eth0 xdpdrv off
echo "detach rc=$?"
nsenter -t "$PID" -n ip -d link show eth0 | grep -ci xdp

if [ "$FAIL" -eq 0 ]; then echo "== STEP1 DONE: PASS =="; else echo "== STEP1 DONE: FAIL =="; fi
exit $FAIL
