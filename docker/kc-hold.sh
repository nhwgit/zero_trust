#!/usr/bin/env bash
# 스모크용 — Keycloak을 띄우고 WSL 세션을 살려둔다(컨테이너 유지).
# host에서 localhost:8081로 접근 가능. 종료는 docker compose down으로.
set -uo pipefail
cd "$(dirname "$0")"

docker compose -f docker-compose.yml up -d

echo "== waiting for ztg realm discovery =="
ready=no
for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:8081/realms/ztg/.well-known/openid-configuration || true)
  if [ "$code" = "200" ]; then
    echo "KC_READY iter=$i"
    ready=yes
    break
  fi
  sleep 2
done

if [ "$ready" != "yes" ]; then
  echo "KC_NOT_READY"
  docker logs --tail 30 ztg-keycloak
  exit 1
fi

# 세션을 살려둬 컨테이너가 idle로 죽지 않게 한다.
echo "HOLDING (sleep 900)"
sleep 900
