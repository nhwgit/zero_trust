#!/bin/bash
# Step 0: hello-XDP 컴파일 → ztg-gateway veth에 native(xdpdrv) attach/detach 스파이크 (root)
# 관측 방향 실험 포함: (A) host-side veth peer = 컨테이너발 패킷 RX, (B) 컨테이너 netns eth0 = 컨테이너行 ingress RX
PROJ=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/xdp
OUT=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/xdp/out/step0-spike.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool

echo "== 1. compile =="
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c "$PROJ/hello_xdp.c" -o /tmp/hello_xdp.o
echo "compile rc=$?"
ls -l /tmp/hello_xdp.o

echo "== 2. resolve ztg-gateway veth (컨테이너 재생성마다 바뀌므로 매번 해석) =="
PID=$(docker inspect -f '{{.State.Pid}}' ztg-gateway)
PEERIDX=$(nsenter -t "$PID" -n ip -o link show eth0 | sed -n 's/.*eth0@if\([0-9]*\).*/\1/p')
VETH=$(ip -o link | awk -F': ' -v i="$PEERIDX" '$1==i{print $2}' | cut -d@ -f1)
GWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ztg-gateway)
echo "pid=$PID peeridx=$PEERIDX veth=$VETH gwip=$GWIP"

echo "== 3A. native attach: host-side veth =="
ip link set dev "$VETH" xdpdrv obj /tmp/hello_xdp.o sec xdp
RC=$?
echo "attach rc=$RC"
if [ "$RC" -ne 0 ]; then
    echo "-- xdpdrv 실패 → 오프로드(gro/tso) 조정 후 재시도"
    apt-get install -y -qq ethtool >/dev/null 2>&1
    ethtool -K "$VETH" gro on 2>&1
    nsenter -t "$PID" -n ethtool -K eth0 gro on tso off gso off 2>&1
    ip link set dev "$VETH" xdpdrv obj /tmp/hello_xdp.o sec xdp
    echo "retry rc=$?"
fi
ip -d link show "$VETH" | grep -iE 'xdp|prog'
"$BPFTOOL" net show

echo "== 4A. traffic(ping 3회) → map dump: host-side는 '컨테이너발' 패킷만 셀 것 =="
ping -c 3 -W 1 "$GWIP" | tail -2
"$BPFTOOL" map dump name pkt_count

echo "== 5A. detach host-side =="
ip link set dev "$VETH" xdpdrv off
echo "detach rc=$?"
ip -d link show "$VETH" | grep -ci xdp

echo "== 3B. native attach: 컨테이너 netns 안 eth0 (ingress 관측 지점) =="
nsenter -t "$PID" -n ip link set dev eth0 xdpdrv obj /tmp/hello_xdp.o sec xdp
echo "attach rc=$?"
nsenter -t "$PID" -n ip -d link show eth0 | grep -iE 'xdp|prog'

echo "== 4B. traffic(ping 3회) → map dump: 컨테이너行 ingress를 셀 것 =="
ping -c 3 -W 1 "$GWIP" | tail -2
"$BPFTOOL" map dump name pkt_count

echo "== 5B. detach netns eth0 =="
nsenter -t "$PID" -n ip link set dev eth0 xdpdrv off
echo "detach rc=$?"

echo "== SPIKE DONE =="
