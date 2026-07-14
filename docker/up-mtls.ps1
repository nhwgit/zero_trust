# 서비스간 mTLS 라이브 스택 기동
#
# up-loadtest.ps1과 동일 구조(핫패스 JVM 4개 = Windows bootRun, Keycloak = WSL docker)에
# mtls 프로파일을 입혀 gateway↔pdp↔pip 내부 호출을 상호 TLS로 잠근다.
#   · gateway/pdp/pip에 SPRING_PROFILES_ACTIVE=mtls 주입 → application-mtls.yml 활성.
#   · pdp(8084)/pip(8083) = https+클라인증서 필수(client-auth: need). 관리 플레인은 평문(pdp 8094 / pip 8093).
#   · 인증서는 docker/certs/ (없으면 gen-certs.ps1로 생성).
#
# 사용:
#   .\docker\up-mtls.ps1          # 인증서 생성(필요 시) + Keycloak + JVM 4개 기동 + health 폴링
#   .\docker\smoke-mtls.ps1       # mTLS 핸드셰이크/우회차단 스모크
# 종료: .\docker\down-loadtest.ps1 (포트 8080/8082/8083/8084 — 동일)
$ErrorActionPreference = 'Stop'

$root    = Split-Path $PSScriptRoot -Parent         # 리포 루트(gradlew 기준)
$certDir = Join-Path $PSScriptRoot 'certs'          # 절대경로 — bootRun 작업 디렉터리(모듈 폴더)와 무관하게 주입
$distro  = 'Ubuntu-24.04'
$composeDir = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker'

# ── 0) 인증서 (없으면 생성) ─────────────────────────────────────────────────
if (-not (Test-Path (Join-Path $PSScriptRoot 'certs\ca.p12'))) {
  Write-Host '== 인증서 생성 (docker/certs 없음) ==' -ForegroundColor Cyan
  & (Join-Path $PSScriptRoot 'gen-certs.ps1')
}

# ── 1) Keycloak (WSL docker) ────────────────────────────────────────────────
Write-Host '== Keycloak 기동 (WSL docker compose) ==' -ForegroundColor Cyan
wsl -d $distro -- bash -c "cd $composeDir && docker compose -f docker-compose.yml up -d keycloak"
if ($LASTEXITCODE -ne 0) { throw 'Keycloak compose up 실패 (WSL docker 확인)' }

# ── 2) 핫패스 JVM 4개 (Windows bootRun, 별도 창) ─────────────────────────────
# bootRun 작업 디렉터리는 리포 루트 → application-mtls.yml의 file:docker/certs/* 상대경로가 맞는다.
function Start-Jvm([string]$module, [hashtable]$envVars) {
  $lines = @()
  foreach ($k in $envVars.Keys) { $lines += "`$env:$k='$($envVars[$k])'" }
  $lines += "Set-Location '$root'"
  $lines += ".\gradlew.bat :$module`:bootRun"
  $cmd = $lines -join '; '
  Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd | Out-Null
  Write-Host "  started :$module" -ForegroundColor DarkGray
}

Write-Host '== 핫패스 JVM 4개 기동 (별도 창, mtls 프로파일) ==' -ForegroundColor Cyan
Start-Jvm 'pip'          @{ SPRING_PROFILES_ACTIVE = 'mtls'; ZTG_CERT_DIR = $certDir }
Start-Jvm 'pdp'          @{ SPRING_PROFILES_ACTIVE = 'mtls'; ZTG_CERT_DIR = $certDir; BUSINESS_HOUR_START = '0'; BUSINESS_HOUR_END = '24' }
Start-Jvm 'resource-api' @{}                                   # resource-api는 mTLS 범위 밖(평문 유지)
Start-Jvm 'gateway'      @{ SPRING_PROFILES_ACTIVE = 'mtls'; ZTG_CERT_DIR = $certDir }

# ── 3) health 폴링 ───────────────────────────────────────────────────────────
# pdp/pip는 데이터 포트(8084/8083)가 mTLS라 cert 없이는 못 닿는다 → 평문 관리 포트(8094/8093)로 폴링.
function Wait-Url([string]$name, [string]$url, [int]$timeoutSec) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  do {
    try {
      $code = [int](Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5).StatusCode
      if ($code -eq 200) { Write-Host "  UP   $name" -ForegroundColor Green; return $true }
    } catch {}
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  Write-Host "  DOWN $name ($url)" -ForegroundColor Red
  return $false
}

Write-Host '== health 폴링 (최대 120s) ==' -ForegroundColor Cyan
$ok = $true
$ok = (Wait-Url 'keycloak(8081)'        'http://localhost:8081/realms/ztg/.well-known/openid-configuration' 120) -and $ok
$ok = (Wait-Url 'pip(mgmt 8093)'        'http://localhost:8093/actuator/health' 120) -and $ok
$ok = (Wait-Url 'pdp(mgmt 8094)'        'http://localhost:8094/actuator/health' 120) -and $ok
$ok = (Wait-Url 'resource-api(8082)'    'http://localhost:8082/actuator/health' 120) -and $ok
$ok = (Wait-Url 'gateway(8080)'         'http://localhost:8080/actuator/health' 120) -and $ok

Write-Host ''
if (-not $ok) {
  Write-Warning '일부 서비스가 안 떴다 — 해당 bootRun 창의 로그를 확인하라.'
  exit 1
}
Write-Host 'OK: 5개 서비스 기동 완료 (pdp/pip 데이터 포트 mTLS). 이제:' -ForegroundColor Green
Write-Host '    .\docker\smoke-mtls.ps1' -ForegroundColor Yellow
