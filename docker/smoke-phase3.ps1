# Phase 3 스모크 — PDP/PIP 정책 분리 검증 (Windows/PowerShell)
# 전제: 아래 5개가 모두 떠 있어야 한다.
#   Keycloak(8081):     wsl bash docker/kc-hold.sh
#   pip(8083):          .\gradlew.bat :pip:bootRun
#   pdp(8084):          .\gradlew.bat :pdp:bootRun
#   resource-api(8082): .\gradlew.bat :resource-api:bootRun
#   gateway(8080):      .\gradlew.bat :gateway:bootRun
#
# ⚠️ payroll ALLOW는 "업무시간(기본 09-18)"을 조건으로 둔다. 이 스모크는 시각과 무관하게
#    돌릴 수 있도록 pdp를 넓은 창으로 띄우길 권장한다(시간 축은 단위 테스트가 고정 Clock으로 검증):
#       $env:BUSINESS_HOUR_START=0; $env:BUSINESS_HOUR_END=24; .\gradlew.bat :pdp:bootRun
#
# 검증 핵심(완료 기준): PIP 속성(부서/디바이스/위험)을 바꾸면 동일 사용자 alice의 /api/payroll
#   결과가 ALLOW(200) ↔ DENY(403)로 뒤집힌다.
$ErrorActionPreference = "Stop"

$GW   = "http://localhost:8080"   # 외부 진입점(PEP)
$RES  = "http://localhost:8082"   # 백엔드(직접 호출은 막혀야 함)
$PIP  = "http://localhost:8083"   # 속성 저장소(데모용 변경 대상)
$pass = 0; $fail = 0

function Token([string]$user, [string]$pw) {
  $body = @{ grant_type="password"; client_id="ztg-api"; client_secret="ztg-api-secret"; username=$user; password=$pw }
  (Invoke-RestMethod -Method Post -Uri "http://localhost:8081/realms/ztg/protocol/openid-connect/token" -Body $body).access_token
}

# 응답 코드만 얻는다. Windows PowerShell 5.1은 4xx/5xx에서 예외를 던지므로 직접 캐치한다.
function Code([string]$url, [hashtable]$headers) {
  try {
    $r = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -TimeoutSec 10
    return [int]$r.StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return -1
  }
}

# PIP에 주체 속성을 덮어쓴다(데모용 조건 변경).
function SetAttr([string]$subject, [string]$dept, [bool]$trusted, [int]$risk) {
  $body = @{ department=$dept; deviceTrusted=$trusted; riskScore=$risk } | ConvertTo-Json
  Invoke-RestMethod -Method Put -Uri "$PIP/pip/attributes/$subject" -Body $body -ContentType "application/json" | Out-Null
}

function Check([string]$name, [int]$got, [int]$want) {
  if ($got -eq $want) { Write-Host "  PASS  $name (got $got)" -ForegroundColor Green; $script:pass++ }
  else { Write-Host "  FAIL  $name (got $got, want $want)" -ForegroundColor Red; $script:fail++ }
}

$hour = (Get-Date).Hour
if ($hour -lt 9 -or $hour -ge 18) {
  Write-Host "※ 현재 시각이 업무시간(09-18) 밖입니다. pdp를 BUSINESS_HOUR_START=0/END=24로 띄우지 않았다면 payroll ALLOW 케이스가 DENY로 나옵니다." -ForegroundColor Yellow
}

Write-Host "== 토큰 발급 ==" -ForegroundColor Cyan
$alice = Token "alice" "alice123"
$bob   = Token "bob"   "bob123"
$hAlice = @{ Authorization = "Bearer $alice" }
$hBob   = @{ Authorization = "Bearer $bob" }

Write-Host "`n== 0) Phase 2 회귀(인증/PEP 경유) ==" -ForegroundColor Cyan
Check "게이트웨이 무토큰 /api/hello -> 401"        (Code "$GW/api/hello" @{})  401
Check "직접호출(우회) /api/hello -> 403"           (Code "$RES/api/hello" $hAlice) 403
Check "게이트웨이 alice /api/hello -> 200"         (Code "$GW/api/hello" $hAlice) 200

Write-Host "`n== 1) payroll 기본 정책: alice = finance/신뢰/저위험 -> ALLOW ==" -ForegroundColor Cyan
SetAttr "alice" "finance" $true 10
Check "alice /api/payroll -> 200 (ALLOW)"          (Code "$GW/api/payroll" $hAlice) 200

Write-Host "`n== 2) 부서 조건 위반: alice -> engineering -> DENY ==" -ForegroundColor Cyan
SetAttr "alice" "engineering" $true 10
Check "alice /api/payroll -> 403 (부서)"           (Code "$GW/api/payroll" $hAlice) 403

Write-Host "`n== 3) 디바이스 조건 위반: alice finance/비신뢰 -> DENY ==" -ForegroundColor Cyan
SetAttr "alice" "finance" $false 10
Check "alice /api/payroll -> 403 (디바이스)"       (Code "$GW/api/payroll" $hAlice) 403

Write-Host "`n== 4) 위험적응: alice 고위험(95) -> 모든 리소스 DENY ==" -ForegroundColor Cyan
SetAttr "alice" "finance" $true 95
Check "alice /api/payroll -> 403 (위험)"           (Code "$GW/api/payroll" $hAlice) 403
Check "alice /api/hello   -> 403 (위험: 전 리소스)" (Code "$GW/api/hello" $hAlice) 403

Write-Host "`n== 5) 조건 원복 -> 다시 ALLOW (ALLOW↔DENY 가역성 증명) ==" -ForegroundColor Cyan
SetAttr "alice" "finance" $true 10
Check "alice /api/payroll -> 200 (복귀)"           (Code "$GW/api/payroll" $hAlice) 200

Write-Host "`n== 6) 다른 사용자 bob = engineering -> payroll DENY ==" -ForegroundColor Cyan
Check "bob /api/payroll -> 403 (부서)"             (Code "$GW/api/payroll" $hBob) 403

Write-Host "`n== 결과: $pass PASS / $fail FAIL ==" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
