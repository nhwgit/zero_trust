# 부하테스트 라이브 스택 기동 (측정 신뢰성 통제 내장)
#
# 핫패스 JVM 4개는 Windows에서 bootRun(각 별도 창), Keycloak은 WSL docker.
# 측정 신뢰성 통제:
#   · 모든 JVM에 LOGGING_LEVEL_COM_ZTG=WARN 주입 → 요청당 INFO 로그 I/O가 지연을 지배하지 않게.
#   · PDP는 BUSINESS_HOUR 0~24 → 업무시간 조건으로 /api 경로가 DENY로 새지 않게(측정은 /api/hello).
#
# 사용:
#   .\docker\up-loadtest.ps1          # Keycloak(WSL) + JVM 4개 기동 후 health 폴링
#   k6 run .\docker\loadtest.js       # 기동 확인되면 부하 스모크
# 종료: 각 bootRun 창을 닫는다(또는 .\docker\down-loadtest.ps1). Keycloak: wsl docker compose ... down
$ErrorActionPreference = 'Stop'

$root   = Split-Path $PSScriptRoot -Parent          # 리포 루트(gradlew 위치)
$distro = 'Ubuntu-24.04'
$composeDir = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker'

# ── 0) Keycloak (WSL docker) ────────────────────────────────────────────────
Write-Host '== Keycloak 기동 (WSL docker compose) ==' -ForegroundColor Cyan
wsl -d $distro -- bash -c "cd $composeDir && docker compose -f docker-compose.yml up -d keycloak"
if ($LASTEXITCODE -ne 0) { throw 'Keycloak compose up 실패 (WSL docker 확인)' }

# ── 1) 핫패스 JVM 4개 (Windows bootRun, 별도 창, WARN 로그 주입) ─────────────
# 각 창에서: 환경변수 세팅 → gradlew :MOD:bootRun. -NoExit로 창을 살려 둔다(로그/종료용).
function Start-Jvm([string]$module, [hashtable]$envVars) {
  $lines = @("`$env:LOGGING_LEVEL_COM_ZTG='WARN'")          # 공통 통제: 요청당 INFO 로그 끄기
  foreach ($k in $envVars.Keys) { $lines += "`$env:$k='$($envVars[$k])'" }
  $lines += "Set-Location '$root'"
  $lines += ".\gradlew.bat :$module`:bootRun"
  $cmd = $lines -join '; '
  Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd | Out-Null
  Write-Host "  started :$module (bootRun, WARN)" -ForegroundColor DarkGray
}

Write-Host '== 핫패스 JVM 4개 기동 (별도 창) ==' -ForegroundColor Cyan
Start-Jvm 'pip'          @{}
Start-Jvm 'pdp'          @{ BUSINESS_HOUR_START = '0'; BUSINESS_HOUR_END = '24' }
Start-Jvm 'resource-api' @{}
Start-Jvm 'gateway'      @{}

# ── 2) health 폴링 (bootRun JVM 기동에 수십 초) ──────────────────────────────
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
$ok = (Wait-Url 'keycloak(8081)'     'http://localhost:8081/realms/ztg/.well-known/openid-configuration' 120) -and $ok
$ok = (Wait-Url 'pip(8083)'          'http://localhost:8083/actuator/health' 120) -and $ok
$ok = (Wait-Url 'pdp(8084)'          'http://localhost:8084/actuator/health' 120) -and $ok
$ok = (Wait-Url 'resource-api(8082)' 'http://localhost:8082/actuator/health' 120) -and $ok
$ok = (Wait-Url 'gateway(8080)'      'http://localhost:8080/actuator/health' 120) -and $ok

Write-Host ''
if (-not $ok) {
  Write-Warning '일부 서비스가 안 떴다 — 해당 bootRun 창의 로그를 확인하라.'
  exit 1
}
Write-Host 'OK: 5개 서비스 기동 완료. 이제 부하 스모크:' -ForegroundColor Green
Write-Host '    k6 run .\docker\loadtest.js' -ForegroundColor Yellow
