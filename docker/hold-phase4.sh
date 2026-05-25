#!/usr/bin/env bash
# Phase 4 Step 2 검증용 — keycloak+prometheus+grafana를 띄우고 WSL 세션을 살려둔다.
# (WSL idle이면 distro가 종료되며 컨테이너가 죽으므로 sleep으로 hold)
set -uo pipefail
cd "$(dirname "$0")"

WINDOWS_HOST_IP="$(ip route show default | awk '/default/ {print $3; exit}')"
export WINDOWS_HOST_IP
echo "WINDOWS_HOST_IP=${WINDOWS_HOST_IP}"

docker compose -f docker-compose.yml up -d
echo "HOLDING (sleep 1800)"
sleep 1800
