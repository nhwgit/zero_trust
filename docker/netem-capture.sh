#!/usr/bin/env bash
# L4 netem 캡처 오케스트레이션 (단일 WSL 세션 = VM 안정). 호스트 k6가 mtls 8083에 안 닿는 문제를
# 피해 WSL 내부 curl 루프로 부하를 만든다. 체인은 ALLOW/DENY 무관하게 gw->pdp->pip(8083)을 타므로
# netem L4 영향 캡처엔 충분하고, time_total로 p50/p90/p99도 산출한다.
#   사용: bash _netem-run.sh <before|after> [캡처초=30] [요청수=180]
set -u
LABEL="${1:?before|after}"
SECS="${2:-30}"
N="${3:-180}"
PS=/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docs/packet-study
OUT="$PS/netem-${LABEL}.pcap"
TIMES="/tmp/netem-${LABEL}-times.txt"

echo "== [$LABEL] 토큰 발급 =="
TOKEN=$(curl -s -X POST localhost:8081/realms/ztg/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ztg-api -d client_secret=ztg-api-secret \
  -d username=alice -d password=alice123 \
  | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/.*:"//; s/"$//')
echo "token len=${#TOKEN}"
[ "${#TOKEN}" -lt 20 ] && { echo "토큰 발급 실패 — 중단"; exit 1; }

echo "== [$LABEL] 캡처 시작 (pdp netns, ${SECS}s) -> netem-${LABEL}.pcap =="
docker run --rm --net container:ztg-pdp nicolaka/netshoot \
  timeout "${SECS}" tcpdump -i any -U -w - 'tcp port 8083 or tcp port 8084' \
  > "$OUT" 2>/tmp/tcpdump-${LABEL}.log &
CAPPID=$!
sleep 4   # tcpdump가 netns에 바인딩될 시간(0패킷 함정 방지)

echo "== [$LABEL] 부하 ${N}회 (gw /api/hello) =="
: > "$TIMES"
for i in $(seq 1 "$N"); do
  curl -s -o /dev/null -w '%{http_code} %{time_total}\n' \
    -H "Authorization: Bearer $TOKEN" localhost:8080/api/hello >> "$TIMES"
done

echo "== [$LABEL] 부하 끝, 캡처 종료 대기 =="
wait "$CAPPID"

echo "== [$LABEL] 결과 =="
ls -l "$OUT" | awk '{print "pcap bytes="$5}'
echo "HTTP 코드 분포:"; awk '{print $1}' "$TIMES" | sort | uniq -c
echo "지연 time_total(초) 분포:"
awk '{print $2}' "$TIMES" | sort -n | awk '{a[NR]=$1} END{
  if(NR==0){print "no samples"; exit}
  printf "  n=%d  p50=%.4f  p90=%.4f  p99=%.4f  max=%.4f\n", NR, a[int(NR*0.50)], a[int(NR*0.90)], a[int(NR*0.99)], a[NR]
}'
