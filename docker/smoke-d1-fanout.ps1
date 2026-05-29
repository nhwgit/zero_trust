# D1 ④ fan-out 스모크 — 다중 게이트웨이 능동 무효화(Redis pub/sub) (Windows/PowerShell)
#
# 무엇을 증명하나(= resume.md D1 ④): 한 게이트웨이(GW1)에서 위험이 올라 PIP가 epoch를 bump하면,
# PIP가 Redis 채널로 publish하고 "위험을 유발하지 않은" GW2도 그 메시지를 받아 캐시를 즉시 키-아웃한다.
# 그래서 GW2는 자기 PDP 왕복(=옛 epoch 학습)을 기다리지 않고, TTL이 남았는데도 다음 요청부터 재평가한다 →
# 같은 토큰·재로그인 없이 GW2의 ALLOW가 DENY로 전이한다. (fan-out이 없었다면 GW2는 TTL 동안 옛 ALLOW 유지.)
#
# 지렛대로 IP 변화(+30, PIP 전역 lastSeenIp)를 쓴다 — 레이트는 게이트웨이별 관측이라 노드 간 전파가 안 되지만,
# IP/epoch는 PIP가 전역으로 들고 있어 fan-out 효과(노드 간 ALLOW→DENY)가 깨끗하게 드러난다.
#
# 전제(모두 bootRun = 평문. PIP attribute PUT 때문에 평문 PIP가 필요. Redis만 컨테이너):
#   Redis(6379):   docker compose -f docker/docker-compose.yml -f docker/compose-fanout.yml up -d redis
#   Keycloak(8081): wsl bash docker/kc-hold.sh
#   resource-api(8082): .\gradlew.bat :resource-api:bootRun
#   pdp(8084):     $env:BUSINESS_HOUR_START=0; $env:BUSINESS_HOUR_END=24; .\gradlew.bat :pdp:bootRun
#   pip(8083):     $env:FANOUT_ENABLED="true"; $env:REDIS_HOST="localhost";
#                  $env:ZTG_PIP_RISK_BUSINESS_HOUR_START=0; $env:ZTG_PIP_RISK_BUSINESS_HOUR_END=24;
#                  .\gradlew.bat :pip:bootRun
#   gateway(8080): $env:FANOUT_ENABLED="true"; $env:REDIS_HOST="localhost";
#                  $env:DECISION_CACHE_TTL="30s"; $env:DECISION_CACHE_HIGH_RISK_SCORE="70";
#                  .\gradlew.bat :gateway:bootRun
#   gateway2(8090):$env:SERVER_PORT=8090; $env:FANOUT_ENABLED="true"; $env:REDIS_HOST="localhost";
#                  $env:DECISION_CACHE_TTL="30s"; $env:DECISION_CACHE_HIGH_RISK_SCORE="70";
#                  .\gradlew.bat :gateway:bootRun
#
#   - TTL 30s + high-risk-score 70: GW2가 캐시한 home ALLOW(score 50<70)는 30초간 산다 → fan-out이 없으면
#     스모크 내내 200이어야 한다. 그 30초 창 안에서 GW2가 403으로 뒤집히면 그건 TTL이 아니라 fan-out이다.
#   - 업무시간 0-24로 off-hours(+15)를 빼 점수를 결정적으로 둔다(이 스모크는 'fan-out' 축만 본다).
#
# 점수 산식(alice=finance+미신뢰, baseline 10, PDP 위험임계 80):
#   home IP        = baseline 10 + device 40            = 50  (< 80 => ALLOW)
#   다른(새) IP    = 10 + 40 + ip-change 30             = 80  (>= 80 => DENY)
$ErrorActionPreference = "Stop"

$GW1  = "http://localhost:8080"
$GW2  = "http://localhost:8090"
$PIP  = "http://localhost:8083"
$HomeIp = "203.0.113.10"   # alice의 평소 출발지(PIP의 직전 관측 기준)
$NewIp  = "198.51.100.66"  # GW1에서 위험을 올리는 낯선 출발지
$pass = 0; $fail = 0

function Token([string]$user, [string]$pw) {
  $body = @{ grant_type="password"; client_id="ztg-api"; client_secret="ztg-api-secret"; username=$user; password=$pw }
  (Invoke-RestMethod -Method Post -Uri "http://localhost:8081/realms/ztg/protocol/openid-connect/token" -Body $body).access_token
}

function CodeFrom([string]$url, [string]$token, [string]$ip) {
  $headers = @{ Authorization = "Bearer $token"; "X-Forwarded-For" = $ip }
  try {
    $r = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -TimeoutSec 10
    return [int]$r.StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return -1
  }
}

function SetAttr([string]$subject, [string]$dept, [bool]$trusted, [int]$risk) {
  $body = @{ department=$dept; deviceTrusted=$trusted; riskScore=$risk } | ConvertTo-Json
  Invoke-RestMethod -Method Put -Uri "$PIP/pip/attributes/$subject" -Body $body -ContentType "application/json" | Out-Null
}

function Check([string]$name, [int]$got, [int]$want) {
  if ($got -eq $want) { Write-Host "  PASS  $name (got $got)" -ForegroundColor Green; $script:pass++ }
  else { Write-Host "  FAIL  $name (got $got, want $want)" -ForegroundColor Red; $script:fail++ }
}

Write-Host "== 토큰 발급 (이후 한 번도 재발급하지 않는다 = 재로그인 없음) ==" -ForegroundColor Cyan
$alice = Token "alice" "alice123"
SetAttr "alice" "finance" $false 10   # 미신뢰 디바이스 → home 50(ALLOW) / 새 IP 80(DENY)

Write-Host "`n== 0) 두 게이트웨이 모두 home IP로 워밍업 → 각자 ALLOW@epoch0를 캐시 ==" -ForegroundColor Cyan
# GW1 첫 요청: lastSeenIp=null이라 ip-change 없음 → score 50 → ALLOW, PIP가 lastSeenIp=home으로 고정.
CodeFrom "$GW1/api/hello" $alice $HomeIp | Out-Null
Check "GW1 alice /api/hello (home IP) -> 200 ALLOW" (CodeFrom "$GW1/api/hello" $alice $HomeIp) 200
# GW2도 home으로 캐시를 채운다(별도 인스턴스라 캐시는 독립). PIP는 home==lastSeenIp라 점수/epoch 불변.
Check "GW2 alice /api/hello (home IP) -> 200 ALLOW (GW2 캐시에 ALLOW@epoch0)" (CodeFrom "$GW2/api/hello" $alice $HomeIp) 200

Write-Host "`n== 1) GW1에서만 위험을 올린다: 새 IP → ip-change(+30) → score 80 → DENY → epoch bump ==" -ForegroundColor Cyan
Write-Host "   이 평가에서 PIP가 epoch를 0→1로 올리고 Redis 채널로 (alice,1)을 publish한다. PIP lastSeenIp:=new." -ForegroundColor DarkGray
Check "GW1 alice /api/hello (NEW IP) -> 403 DENY" (CodeFrom "$GW1/api/hello" $alice $NewIp) 403

Write-Host "`n== 2) fan-out 전파 대기(짧게) — GW2가 (alice,1)을 받아 자기 캐시를 키-아웃한다 ==" -ForegroundColor Cyan
Start-Sleep -Milliseconds 800   # pub/sub은 거의 즉시지만 리스너 스레드 반영 여유. TTL 30s 안이라 'TTL 아님'이 보장된다.

Write-Host "`n== 3) 헤드라인: GW2는 새 IP를 본 적 없고 TTL(30s)도 안 지났지만 home 요청이 ALLOW→DENY로 전이 ==" -ForegroundColor Cyan
Write-Host "   GW2의 ALLOW@epoch0가 fan-out으로 키-아웃 → 미스 → 재평가. PIP lastSeenIp=new라 home도 ip-change(new->home)" -ForegroundColor DarkGray
Write-Host "   → score 80 → DENY. fan-out이 없었다면 GW2는 30s TTL 동안 옛 ALLOW를 그대로 200으로 냈을 것이다." -ForegroundColor DarkGray
Check "GW2 alice /api/hello (home IP) -> 403 DENY (재로그인 없이, 노드 간 전파)" (CodeFrom "$GW2/api/hello" $alice $HomeIp) 403

Write-Host "`n== 결과: $pass PASS / $fail FAIL ==" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
