# 서비스간 mTLS 라이브 스택 — 전부 컨테이너로 (D2 — 패킷레벨 관측, 선택지 B).
#
# up-mtls.ps1(핫패스 4개 = Windows bootRun)과 달리, 4개를 모두 도커 컨테이너로 올려
# 서비스간 mTLS 통신을 리눅스 브리지에 태운다 → WSL tcpdump 하나로 mTLS 핸드셰이크까지 캡처된다.
#
# 사용:
#   .\docker\up-mtls-docker.ps1     # bootJar 빌드 + 인증서(컨테이너 SAN) + compose build/up + health 폴링
#   .\docker\capture-mtls.ps1       # (사용자) tcpdump 캡처 시작
#   .\docker\smoke-mtls.ps1         # 트리거 — 정상 체인/우회차단 스모크(포트 동일하므로 그대로 재사용)
# 종료: .\docker\down-mtls-docker.ps1
#
# ⚠️ 호스트 bootRun mTLS 스택(up-mtls.ps1)과 포트가 겹친다(8080/8082/8083/8084/8093/8094) — 동시 기동 금지.
$ErrorActionPreference = 'Stop'

$root       = Split-Path $PSScriptRoot -Parent
$certDir    = Join-Path $PSScriptRoot 'certs'
$distro     = 'Ubuntu-24.04'
$composeDir = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker'
$composeArgs = '-f docker-compose.yml -f compose-apps.yml'

# ── 0) bootJar 빌드 (호스트) — Dockerfile은 이 jar를 복사만 한다 ────────────────
Write-Host '== bootJar 빌드 (gateway/pdp/pip/resource-api) ==' -ForegroundColor Cyan
& (Join-Path $root 'gradlew.bat') ':gateway:bootJar' ':pdp:bootJar' ':pip:bootJar' ':resource-api:bootJar'
if ($LASTEXITCODE -ne 0) { throw 'bootJar 빌드 실패' }

# ── 1) 인증서 (컨테이너 SAN) ─────────────────────────────────────────────────
# 기존 certs는 SAN=localhost만이라 컨테이너 호스트네임(pdp/pip) 검증에 실패한다.
# 컨테이너용 SAN(dns:pdp 등)으로 한 번 재발급하고 마커로 표시한다(이후 재사용 — localhost도 포함돼 호스트 경로와 호환).
$marker = Join-Path $certDir '.containerized'
if (-not (Test-Path $marker)) {
  Write-Host '== 인증서 재발급 (컨테이너 SAN: dns:pdp/pip/gateway) ==' -ForegroundColor Cyan
  if (Test-Path $certDir) { Remove-Item -Recurse -Force $certDir }
  & (Join-Path $PSScriptRoot 'gen-certs.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'gen-certs 실패' }
  New-Item -ItemType File -Path $marker | Out-Null
}

# ── 2) compose build + up (WSL docker) ───────────────────────────────────────
Write-Host '== compose build + up (keycloak + 4개 앱, WSL docker) ==' -ForegroundColor Cyan
wsl -d $distro -- bash -c "cd $composeDir && docker compose $composeArgs up -d --build keycloak gateway pdp pip resource-api"
if ($LASTEXITCODE -ne 0) { throw 'compose up 실패 (WSL docker 확인)' }

# ── 2.5) WSL keepalive ───────────────────────────────────────────────────────
# WSL VM은 유휴(vmIdleTimeout, 기본 ~60s)면 내려가며 dockerd째 컨테이너를 죽인다(Exit 255).
# restart 정책이 VM 복귀 시 컨테이너를 살리지만, 호스트→localhost 캡처/스모크는 VM이 떠 있어야 닿는다.
# ⚠️ `wsl -- bash -c "... &"`는 세션을 열자마자 닫아 VM을 못 붙잡는다(orphan sleep도 idle-shutdown됨).
# Start-Process로 wsl 세션을 '열어둔 채' 유지해야 VM이 산다. down-mtls-docker.ps1이 sleep을 죽여 해제한다.
wsl -d $distro -- pkill -f 'ztg-keepalive' 2>$null
Start-Process wsl -ArgumentList '-d', $distro, '--', 'bash', '-c', 'exec -a ztg-keepalive sleep 86400' -WindowStyle Hidden
Write-Host '  (WSL keepalive 시작 — down-mtls-docker.ps1이 해제)' -ForegroundColor DarkGray

# ── 3) health 폴링 (호스트 발행 포트) ────────────────────────────────────────
# pdp/pip 데이터 포트(8084/8083)는 mTLS라 cert 없이 못 닿는다 → 평문 관리 포트(8094/8093)로 폴링.
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

Write-Host '== health 폴링 (최대 150s) ==' -ForegroundColor Cyan
$ok = $true
$ok = (Wait-Url 'keycloak(8081)'     'http://localhost:8081/realms/ztg/.well-known/openid-configuration' 150) -and $ok
$ok = (Wait-Url 'pip(mgmt 8093)'     'http://localhost:8093/actuator/health' 150) -and $ok
$ok = (Wait-Url 'pdp(mgmt 8094)'     'http://localhost:8094/actuator/health' 150) -and $ok
$ok = (Wait-Url 'resource-api(8082)' 'http://localhost:8082/actuator/health' 150) -and $ok
$ok = (Wait-Url 'gateway(8080)'      'http://localhost:8080/actuator/health' 150) -and $ok

Write-Host ''
if (-not $ok) {
  Write-Warning '일부 서비스가 안 떴다 — 로그 확인: wsl -d Ubuntu-24.04 -- docker compose logs <svc>'
  exit 1
}
Write-Host 'OK: 5개 컨테이너 기동 완료 (pdp/pip 데이터 포트 mTLS). 이제:' -ForegroundColor Green
Write-Host '    .\docker\capture-mtls.ps1   (캡처 시작) → 다른 창에서 .\docker\smoke-mtls.ps1 (트리거)' -ForegroundColor Yellow
