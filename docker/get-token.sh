#!/usr/bin/env bash
# Keycloak에서 access token을 발급(password grant)받아 payload(claims)를 디코딩해 출력한다.
# 사용: ./get-token.sh [username] [password]
#   예: ./get-token.sh alice alice123
set -euo pipefail

KC="${KC:-http://localhost:8081}"
REALM="${REALM:-ztg}"
CLIENT="${CLIENT:-ztg-api}"
SECRET="${SECRET:-ztg-api-secret}"
USER="${1:-alice}"
PASS="${2:-alice123}"

TOKEN=$(curl -s -X POST \
  "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=$CLIENT" \
  -d "client_secret=$SECRET" \
  -d "username=$USER" \
  -d "password=$PASS" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [ -z "$TOKEN" ]; then
  echo "토큰 발급 실패 — Keycloak가 떠 있는지(http://localhost:8081) 확인" >&2
  exit 1
fi

echo "== access_token =="
echo "$TOKEN"
echo
echo "== payload(claims) =="
# JWT의 두 번째 세그먼트(payload)만 base64url 디코딩
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | sed 's/$/\n/' || true
