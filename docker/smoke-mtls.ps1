# 서비스간 mTLS 스모크 (Phase 6-A) — up-mtls.ps1로 스택을 먼저 띄운 뒤 실행.
#
# 입증 목표:
#   1) 정상 경로: 토큰으로 /api/hello → 200. gateway→pdp(mTLS)→pip(mTLS) 체인이 상호 TLS로 성립함.
#   2) 우회 차단(클라 인증서 없음): pdp:8084 직접 호출 → TLS 핸드셰이크 거부(client-auth: need).
#   3) 대조군(클라 인증서 있음): 같은 호출에 gateway.p12 제시 → TLS는 성립(HTTP 레벨 응답이 돌아옴).
# 2 vs 3의 대비가 "내부 신뢰를 인증서로만 부여한다"(zero-trust)를 증명한다.
$ErrorActionPreference = 'Stop'

$gw       = 'http://localhost:8080'
$pdpData  = 'https://localhost:8084/decision'   # mTLS 데이터 포트
$kc       = 'http://localhost:8081'
$certPath = Join-Path $PSScriptRoot 'certs\gateway.p12'
$certPass = 'ztg-mtls-pass'
$fail = 0

function Pass([string]$m) { Write-Host "  PASS  $m" -ForegroundColor Green }
function Fail([string]$m) { Write-Host "  FAIL  $m" -ForegroundColor Red; $script:fail++ }

# 자체 CA는 Windows 신뢰저장소에 없으므로 서버 인증서 검증은 우회한다(테스트 초점은 '클라 인증서').
$origCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

try {
  # ── 1) 정상 경로: 토큰 발급 → /api/hello → 200 (mTLS 체인 전체 성립) ──────────
  Write-Host '== 1) 정상 경로 (gw→pdp→pip mTLS 체인) ==' -ForegroundColor Cyan
  $tokenResp = Invoke-RestMethod -Method Post -Uri "$kc/realms/ztg/protocol/openid-connect/token" -Body @{
    grant_type = 'password'; client_id = 'ztg-api'; client_secret = 'ztg-api-secret'
    username = 'alice'; password = 'alice123'
  }
  $token = $tokenResp.access_token
  try {
    $r = Invoke-WebRequest -Uri "$gw/api/hello" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing -TimeoutSec 10
    if ([int]$r.StatusCode -eq 200) { Pass "/api/hello 200 — mTLS 내부 호출(gw→pdp→pip) 통과" }
    else { Fail "/api/hello 기대 200, 실제 $($r.StatusCode)" }
  } catch { Fail "/api/hello 호출 실패: $($_.Exception.Message)" }

  # ── 2) 우회 차단: 클라 인증서 없이 pdp:8084 직접 호출 → TLS 거부 ──────────────
  Write-Host '== 2) 우회 차단 (클라 인증서 없음 → TLS 거부) ==' -ForegroundColor Cyan
  try {
    Invoke-WebRequest -Uri $pdpData -Method Post -Body '{}' -ContentType 'application/json' `
      -UseBasicParsing -TimeoutSec 10 | Out-Null
    Fail "클라 인증서 없이 pdp:8084 접속이 성공해버림 (client-auth=need가 안 먹음)"
  } catch {
    Pass "클라 인증서 없는 직접 호출이 거부됨 → $($_.Exception.Message)"
  }

  # ── 3) 대조군: gateway.p12 제시 → TLS 성립(HTTP 레벨 응답) ────────────────────
  Write-Host '== 3) 대조군 (클라 인증서 제시 → TLS 성립) ==' -ForegroundColor Cyan
  $clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $certPass)
  try {
    $r = Invoke-WebRequest -Uri $pdpData -Method Post -Body '{}' -ContentType 'application/json' `
      -Certificate $clientCert -UseBasicParsing -TimeoutSec 10
    Pass "인증서 제시 시 TLS 성립 (HTTP $($r.StatusCode))"
  } catch [System.Net.WebException] {
    # HTTP 레벨 에러(4xx/5xx)는 TLS가 성립했다는 뜻 → 통과. TLS/연결 실패면 응답이 없다.
    $resp = $_.Exception.Response
    if ($resp) { Pass "인증서 제시 시 TLS 성립 (HTTP $([int]$resp.StatusCode))" }
    else { Fail "인증서를 제시했는데도 TLS/연결 실패: $($_.Exception.Message)" }
  } catch { Fail "예상 외 오류: $($_.Exception.Message)" }
}
finally {
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $origCallback
}

Write-Host ''
if ($fail -eq 0) { Write-Host 'OK: mTLS 스모크 전부 통과' -ForegroundColor Green }
else { Write-Host "$fail 건 실패" -ForegroundColor Red; exit 1 }
