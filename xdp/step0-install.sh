#!/bin/bash
# D3 Step 0: XDP 툴체인 설치 (root로 실행)
OUT=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/xdp/out/step0-install.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
export DEBIAN_FRONTEND=noninteractive
echo "== apt update =="
apt-get update -qq
echo "== apt install =="
apt-get install -y -qq clang llvm libbpf-dev linux-tools-common linux-tools-generic
RC=$?
echo "install rc=$RC"
echo "== versions =="
clang --version | head -1
llvm-strip --version | head -1
echo "-- linux-tools dirs:"
ls -d /usr/lib/linux-tools/*/ 2>&1
BPFTOOL=$(ls -d /usr/lib/linux-tools/*/ 2>/dev/null | head -1)bpftool
echo "-- bpftool at: $BPFTOOL"
"$BPFTOOL" version
echo "-- libbpf headers:"
ls /usr/include/bpf/ | head -5
echo "== INSTALL DONE =="
