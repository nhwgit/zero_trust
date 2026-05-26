# Phase 4 Step 3 스모크 — PDP 장애 재현 + fail-close 관측 (Windows/PowerShell)
#
# 완료 기준 검증: PDP가 죽으면 게이트웨이가 의도된 fail-close(403)로 막고,
#   그 사실이 지표(ztg_authz_decisions_total{decision=deny,cause=pdp_error})와
#   응답 헤더(X-Denied-Reason: "PDP unavailable: ...")로 보인다.
#
# 전제: 5개가 모두 떠 있어야 한다(분산 추적 로그도 함께 보려면 각 콘솔을 띄워둘 것).
#   Keycloak(8081):     wsl bash docker/kc-hold.sh
#   pip(8083):          .\gradlew.bat :pip:bootRun
#   pdp(8084):          $env:BUSINESS_HOUR_START=0; $env:BUSINESS_HOUR_END=24; .\gradlew.bat :pdp:bootRun
#   resource-api(8082): .\gradlew.bat :resource-api:bootRun
#   gateway(8080):      .\gradlew.bat :gateway:bootRun
#
# ⚠️ 이 스모크는 8084 포트를 점유한 PDP 프로세스를 강제 종료한다(장애 주입).
#    끝나면 위 pdp:bootRun 명령으로 다시 띄워야 한다.
$ErrorActionPreference = "Stop"

$GW   = "http://localhost:8080"   # 외부 진입점(PEP)
$pass = 0; $fail = 0

function Token([string]$user, [string]$pw) {
  $body = @{ grant_type="password"; client_id="ztg-api"; client_secret="ztg-api-secret"; username=$user; password=$pw }
  (Invoke-RestMethod -Method Post -Uri "http://localhost:8081/realms/ztg/protocol/openid-connect/token" -Body $body).access_token
}

function SetAttr([string]$subject, [string]$dept, [bool]$trusted, [int]$risk) {
  $body = @{ department=$dept; deviceTrusted=$trusted; riskScore=$risk } | ConvertTo-Json
  Invoke-RestMethod -Method Put -Uri "http://localhost:8083/pip/attributes/$subject" -Body $body -ContentType "application/json" | Out-Null
}

# 요청을 보내고 (상태코드, 거부사유헤더, 요청ID헤더)를 함께 돌려준다. 5.1은 4xx/5xx에서 예외 → 직접 캐치.
function Get-Resp([string]$url, [hashtable]$headers) {
  try {
    $r = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -TimeoutSec 10
    return @{ code=[int]$r.StatusCode; reason=$r.Headers['X-Denied-Reason']; rid=$r.Headers['X-Request-Id'] }
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $reason = $resp.Headers['X-Denied-Reason']
      $rid    = $resp.Headers['X-Request-Id']
      return @{ code=[int]$resp.StatusCode; reason=$reason; rid=$rid }
    }
    return @{ code=-1; reason=$null; rid=$null }
  }
}

# 게이트웨이 /actuator/prometheus에서 카운터 값을 읽는다(태그 substring 모두 포함하는 라인들의 합).
function Get-Counter([string]$metric, [string[]]$tags) {
  $text = (Invoke-WebRequest -Uri "$GW/actuator/prometheus" -UseBasicParsing -TimeoutSec 10).Content
  $sum = 0.0
  foreach ($line in $text -split "`n") {
    if (-not $line.StartsWith($metric)) { continue }
    $ok = $true
    foreach ($t in $tags) { if ($line -notmatch [regex]::Escape($t)) { $ok = $false; break } }
    if ($ok -and $line -match '\s([0-9.eE+-]+)\s*$') { $sum += [double]$matches[1] }
  }
  return $sum
}

function Check([string]$name, [bool]$ok, [string]$detail) {
  if ($ok) { Write-Host "  PASS  $name $detail" -ForegroundColor Green; $script:pass++ }
  else     { Write-Host "  FAIL  $name $detail" -ForegroundColor Red;   $script:fail++ }
}

Write-Host "== 0) 전제 점검 ==" -ForegroundColor Cyan
$pdpUp = $false
try { Invoke-WebRequest -Uri "http://localhost:8084/actuator/health" -UseBasicParsing -TimeoutSec 5 | Out-Null; $pdpUp = $true } catch {}
if (-not $pdpUp) { Write-Host "PDP(8084)가 떠 있지 않다. 먼저 pdp:bootRun으로 띄워라." -ForegroundColor Red; exit 1 }

$alice  = Token "alice" "alice123"
$hAlice = @{ Authorization = "Bearer $alice" }
SetAttr "alice" "finance" $true 10   # /api/hello가 ALLOW되도록 저위험 신뢰 상태로 고정

Write-Host "`n== 1) 정상(PDP 살아있음): /api/hello -> 200 ALLOW + 추적 ID 에코 ==" -ForegroundColor Cyan
$traceId = "smoke-trace-" + (Get-Random)
$h1 = $hAlice + @{ 'X-Request-Id' = $traceId }
$r1 = Get-Resp "$GW/api/hello" $h1
Check "ALLOW 200" ($r1.code -eq 200) "(got $($r1.code))"
Check "응답이 보낸 추적 ID를 그대로 에코" ($r1.rid -eq $traceId) "(rid=$($r1.rid))"
Write-Host "    → gateway/resource-api 콘솔에서 requestId=$traceId 로 로그가 상관되는지 확인" -ForegroundColor DarkGray

# fail-close 지표 baseline (장애 주입 전)
$denyBefore = Get-Counter "ztg_authz_decisions_total" @('decision="deny"','cause="pdp_error"')
$errBefore  = Get-Counter "ztg_pdp_requests_seconds_count" @('outcome="error"')
Write-Host ("    baseline: deny/pdp_error={0}, pdp.requests/error={1}" -f $denyBefore, $errBefore) -ForegroundColor DarkGray

Write-Host "`n== 2) 장애 주입: PDP(8084) 프로세스 강제 종료 ==" -ForegroundColor Cyan
$killed = $false
$conns = Get-NetTCPConnection -LocalPort 8084 -State Listen -ErrorAction SilentlyContinue
foreach ($procId in ($conns.OwningProcess | Select-Object -Unique)) {
  try { Stop-Process -Id $procId -Force; $killed = $true; Write-Host "    killed PID $procId" -ForegroundColor DarkGray } catch {}
}
if (-not $killed) { Write-Host "8084 리스너를 못 찾았다." -ForegroundColor Red; exit 1 }
# 포트가 닫힐 때까지 대기(최대 15s)
$deadline = (Get-Date).AddSeconds(15)
do {
  Start-Sleep -Milliseconds 500
  $still = Get-NetTCPConnection -LocalPort 8084 -State Listen -ErrorAction SilentlyContinue
} while ($still -and (Get-Date) -lt $deadline)
Check "PDP 포트 8084 닫힘" (-not $still) ""

Write-Host "`n== 3) PDP 다운 상태: 동일 요청이 fail-close(403)로 막힌다 ==" -ForegroundColor Cyan
$r3 = Get-Resp "$GW/api/hello" $hAlice
Check "fail-close 403" ($r3.code -eq 403) "(got $($r3.code))"
Check "거부 사유 헤더가 PDP 장애를 가리킴" ($r3.reason -like "PDP unavailable:*") "(reason=$($r3.reason))"

Write-Host "`n== 4) 장애가 지표로 보인다(가용성 신호) ==" -ForegroundColor Cyan
Start-Sleep -Seconds 1   # 지표 반영 여유
$denyAfter = Get-Counter "ztg_authz_decisions_total" @('decision="deny"','cause="pdp_error"')
$errAfter  = Get-Counter "ztg_pdp_requests_seconds_count" @('outcome="error"')
Check "deny/pdp_error 카운터 증가" ($denyAfter -gt $denyBefore) "($denyBefore -> $denyAfter)"
Check "pdp.requests outcome=error 증가" ($errAfter -gt $errBefore) "($errBefore -> $errAfter)"

Write-Host "`n== 결과: $pass PASS / $fail FAIL ==" -ForegroundColor Cyan
Write-Host "PDP를 다시 띄워라:  `$env:BUSINESS_HOUR_START=0; `$env:BUSINESS_HOUR_END=24; .\gradlew.bat :pdp:bootRun" -ForegroundColor Yellow
if ($fail -gt 0) { exit 1 }
