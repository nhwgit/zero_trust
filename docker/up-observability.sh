#!/usr/bin/env bash
# 관측 스택(Prometheus/Grafana) 기동 (WSL 내부 실행)
#
# WSL→Windows 게이트웨이 IP를 발견해 WINDOWS_HOST_IP로 export 후 compose up.
# Prometheus가 이 IP를 통해 Windows 호스트의 JVM /actuator/prometheus를 스크랩한다.
set -euo pipefail
cd "$(dirname "$0")"

WINDOWS_HOST_IP="$(ip route show default | awk '/default/ {print $3; exit}')"
export WINDOWS_HOST_IP
echo "[up-observability] WINDOWS_HOST_IP=${WINDOWS_HOST_IP}"

docker compose -f docker-compose.yml up -d prometheus grafana
echo "[up-observability] prometheus -> http://localhost:9090"
echo "[up-observability] grafana    -> http://localhost:3000 (admin/admin, 익명 열람 허용)"
