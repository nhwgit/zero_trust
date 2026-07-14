# Gateway(PEP) 경유 강제 스모크 (Windows/PowerShell)
# 전제: Keycloak(8081) + gateway(8080) + resource-api(8082)가 모두 떠 있어야 한다.
#   Keycloak:     wsl bash docker/kc-hold.sh
#   resource-api: .\gradlew.bat :resource-api:bootRun
#   gateway:      .\gradlew.bat :gateway:bootRun
# 검증: 게이트웨이 우회 직접호출 차단 / 게이트웨이 경유 + 유효 JWT만 통과.
$ErrorActionPreference = "Stop"

$GW   = "http://localhost:8080"   # 외부 진입점(PEP)
$RES  = "http://localhost:8082"   # 백엔드(직접 호출은 막혀야 함)
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

function Check([string]$name, [int]$got, [int]$want) {
  if ($got -eq $want) { Write-Host "  PASS  $name (got $got)" -ForegroundColor Green; $script:pass++ }
  else { Write-Host "  FAIL  $name (got $got, want $want)" -ForegroundColor Red; $script:fail++ }
}

Write-Host "== 토큰 발급 ==" -ForegroundColor Cyan
$alice = Token "alice" "alice123"
$bob   = Token "bob"   "bob123"
$hAlice = @{ Authorization = "Bearer $alice" }
$hBob   = @{ Authorization = "Bearer $bob" }

Write-Host "`n== 1) 게이트웨이 우회(직접 resource-api 호출) 차단 ==" -ForegroundColor Cyan
Check "직접호출 무헤더 /api/hello -> 403"            (Code "$RES/api/hello" @{})        403
Check "직접호출 유효토큰만(신뢰헤더 X) /api/hello -> 403" (Code "$RES/api/hello" $hAlice)  403
Check "직접호출 위조 신뢰헤더 /api/hello -> 403"      (Code "$RES/api/hello" @{ "X-Gateway-Auth"="forged" }) 403

Write-Host "`n== 2) 게이트웨이 경유 정상/거부 흐름 ==" -ForegroundColor Cyan
Check "게이트웨이 무토큰 /api/hello -> 401"           (Code "$GW/api/hello" @{})         401
Check "게이트웨이 잘못된토큰 /api/hello -> 401"        (Code "$GW/api/hello" @{ Authorization="Bearer not-a-jwt" }) 401
Check "게이트웨이 alice /api/hello -> 200"            (Code "$GW/api/hello" $hAlice)     200
Check "게이트웨이 alice /api/admin -> 403"            (Code "$GW/api/admin" $hAlice)     403
Check "게이트웨이 bob   /api/admin -> 200"            (Code "$GW/api/admin" $hBob)       200

Write-Host "`n== 결과: $pass PASS / $fail FAIL ==" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }

