#!/bin/bash
# Step 0: WSL2 XDP 툴체인/커널 프로브 (root로 실행 가정)
OUT=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/xdp/out/step0-probe.out
mkdir -p "$(dirname "$OUT")"
exec > "$OUT" 2>&1
echo "== kernel =="
uname -a
echo "== BTF (/sys/kernel/btf/vmlinux) =="
ls -l /sys/kernel/btf/vmlinux
echo "== bpf syscall / kconfig =="
zgrep -E 'CONFIG_BPF=|CONFIG_BPF_SYSCALL|CONFIG_XDP_SOCKETS|CONFIG_DEBUG_INFO_BTF' /proc/config.gz 2>/dev/null || echo "no /proc/config.gz"
echo "== clang =="
command -v clang && clang --version | head -1
echo "== llvm-strip =="
command -v llvm-strip
echo "== bpftool =="
command -v bpftool && bpftool version
echo "-- /usr/lib/linux-tools contents:"
ls /usr/lib/linux-tools/ 2>&1
echo "== libbpf headers =="
ls /usr/include/bpf/ 2>&1 | head -5
echo "== relevant packages =="
dpkg -l 2>/dev/null | grep -Ei 'libbpf|clang|llvm|linux-tools|bpftool' | awk '{print $1, $2, $3}'
echo "== go =="
command -v go && go version
echo "== docker =="
docker ps --format '{{.Names}} {{.Status}}' 2>&1
echo "== links =="
ip -br link
echo "== PROBE DONE rc=$? =="
