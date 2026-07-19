# 지속검증 / 위험적응 인가 스모크: "재로그인 없이 ALLOW -> DENY -> ALLOW" (Windows/PowerShell)
#
# 무엇을 증명하나:
#   PIP가 위험점수(IP변화·요청레이트)를 산출 -> 위험 상승 시 능동 캐시 무효화(epoch) ->
#   같은 세션·같은 토큰으로 ALLOW가 DENY로 전이(재로그인 없음), 위험이 가시면 다시 ALLOW.
#
# 전제: 아래 5개가 모두 떠 있어야 한다. 데모를 결정적으로 만들려면 권장 환경변수로 띄운다.
#   Keycloak(8081):     wsl bash docker/kc-hold.sh   (백그라운드)
#   resource-api(8082): .\gradlew.bat :resource-api:bootRun
#   pdp(8084):          $env:BUSINESS_HOUR_START=0; $env:BUSINESS_HOUR_END=24; .\gradlew.bat :pdp:bootRun
#   pip(8083):          $env:ZTG_PIP_RISK_BURST_THRESHOLD=5; $env:ZTG_PIP_RISK_BURST_EXIT_THRESHOLD=4;
#                       $env:ZTG_PIP_RISK_BUSINESS_HOUR_START=0; $env:ZTG_PIP_RISK_BUSINESS_HOUR_END=24;
#                       .\gradlew.bat :pip:bootRun
#   gateway(8080):      $env:RATE_BURST_THRESHOLD=5; $env:RATE_BURST_EXIT_THRESHOLD=4; .\gradlew.bat :gateway:bootRun
#
#   - 폭주 임계는 게이트웨이(RATE_BURST_THRESHOLD)와 PIP(ZTG_PIP_RISK_BURST_THRESHOLD)를 같은 값(5)으로
#     맞춘다: 게이트웨이가 밴드를 넘는 순간 캐시를 바이패스(강제 재평가)하고, 그 재평가에서 PIP가 +레이트 가중을 준다.
#   - 해제 임계(exit)도 진입(5) 이하로 낮춰야 한다(기본 40) — 히스테리시스 정합(exit<=enter) fail-fast 때문.
#   - 시각 가중(off-hours)을 빼려고 pip/pdp 업무시간을 0-24로 연다(점수를 예측 가능하게). 위험 신호 축은 이 스모크가,
#     시간 축은 단위 테스트(고정 Clock)가 검증한다.
#   - /api/hello를 쓴다(payroll의 부서/디바이스/시간 게이트와 무관하게 '위험점수' 단일 축만 본다).
#
# 점수 산식(기본 가중치, PDP 위험임계=80):
#   alice = finance + 미신뢰 디바이스 -> baseline 10 + device-untrusted 40 = 50  (< 80 => ALLOW)
#   폭주 발생 시 + rate-burst 40 = 90  (>= 80 => DENY).  폭주가 가시면 다시 50 => ALLOW.
$ErrorActionPreference = "Stop"

$GW   = "http://localhost:8080"
$PIP  = "http://localhost:8083"
$HomeIp = "203.0.113.10"   # alice의 평소 출발지(직전 관측 기준)
$NewIp  = "198.51.100.66"  # '세션 탈취' 시나리오의 낯선 출발지
$Burst  = 10               # 폭주로 쏠 요청 수(임계 5를 윈도우 안에서 넘기기 충분)
$pass = 0; $fail = 0

function Token([string]$user, [string]$pw) {
  $body = @{ grant_type="password"; client_id="ztg-api"; client_secret="ztg-api-secret"; username=$user; password=$pw }
  (Invoke-RestMethod -Method Post -Uri "http://localhost:8081/realms/ztg/protocol/openid-connect/token" -Body $body).access_token
}

# 토큰 + 출발지 IP(X-Forwarded-For 첫 홉)를 실어 GET. 응답 코드만 돌려준다(5.1은 4xx/5xx에서 예외).
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

Write-Host "`n== 0) baseline: alice = finance / 미신뢰 디바이스 (score 50, ALLOW 경계 아래) ==" -ForegroundColor Cyan
SetAttr "alice" "finance" $false 10
# 리셋: 이전 실행이 남긴 위험 맥락(lastSeenIp·ip-change hold)을 비운다(재실행 결정성). ip-change가 hold(기본 30s)로
# 유지되면서 warm-up만으론 부족해졌다 — warm-up 자체가 ip-change를 밟으면 +30이 창 동안 남아 baseline 체크가 깨진다.
# epoch는 보존되므로(게이트웨이 단조 학습과의 정합) 캐시 동작에는 영향이 없다.
Invoke-RestMethod -Method Delete -Uri "$PIP/pip/risk/alice" | Out-Null
# warm-up: home IP를 직전 관측으로 고정한다(리셋 직후 첫 관측 = 변화 아님).
CodeFrom "$GW/api/hello" $alice $HomeIp | Out-Null
Check "정상 alice /api/hello (home IP, 저레이트) -> 200 ALLOW" (CodeFrom "$GW/api/hello" $alice $HomeIp) 200

Write-Host "`n== 1) 동일 IP 폭주 -> 능동 무효화 -> ALLOW에서 DENY로 전이 (재로그인 없이) ==" -ForegroundColor Cyan
Write-Host "   같은 IP라 캐시 키는 그대로지만, 레이트 밴드가 임계를 넘는 순간 게이트웨이가 캐시를 바이패스해" -ForegroundColor DarkGray
Write-Host "   재평가를 유발한다. PIP 점수 50->90(>=80) -> epoch bump -> 옛 ALLOW 키-아웃 -> 403." -ForegroundColor DarkGray
$last = 0
for ($i = 1; $i -le $Burst; $i++) { $last = CodeFrom "$GW/api/hello" $alice $HomeIp }
Check "폭주 중 alice /api/hello (home IP) -> 403 DENY" $last 403

Write-Host "`n== 2) 폭주가 가시면(윈도우 경과) 다시 ALLOW (위험적응 = 영구 차단 아님, 가역적) ==" -ForegroundColor Cyan
Write-Host "   레이트 윈도우(기본 10s)가 비도록 대기 후 1건 -> 밴드가 폭주->정상으로 되넘어가 다시 바이패스->재평가->ALLOW." -ForegroundColor DarkGray
Start-Sleep -Seconds 12
Check "쿨다운 후 alice /api/hello (home IP) -> 200 ALLOW (복귀)" (CodeFrom "$GW/api/hello" $alice $HomeIp) 200

Write-Host "`n== 3) (부가) 낯선 IP에서의 요청 = 즉시 재평가 (캐시 키에 IP 포함 -> 자동 미스) ==" -ForegroundColor Cyan
Write-Host "   새 IP는 ip-change(+30)를 만들어 50->80(>=80) -> 그 hijack 시도 자체가 DENY된다." -ForegroundColor DarkGray
Check "낯선 IP alice /api/hello (NEW IP) -> 403 DENY (재로그인 없이)" (CodeFrom "$GW/api/hello" $alice $NewIp) 403

Write-Host "`n== 4) 재시도 우회 차단: 캐시(고위험 TTL 1s) 만료 후 재시도해도 hold(30s) 동안 DENY 유지 ==" -ForegroundColor Cyan
Write-Host "   hold가 없으면 비교 기준(lastSeenIp)이 새 IP로 덮여 재평가에서 +30이 빠진다 -> 탈취범은 2초 뒤" -ForegroundColor DarkGray
Write-Host "   재시도만 하면 통과했다. hold가 신호를 창으로 늘려 재시도도 같은 DENY를 받는다." -ForegroundColor DarkGray
Start-Sleep -Seconds 2
Check "낯선 IP 재시도 alice /api/hello (NEW IP, 재평가) -> 403 DENY (hold 유지)" (CodeFrom "$GW/api/hello" $alice $NewIp) 403

Write-Host "`n== 결과: $pass PASS / $fail FAIL ==" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
