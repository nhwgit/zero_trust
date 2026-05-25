# Phase 4 Step 2 스모크 — 관측 스택 기동 + Prometheus 4개 타깃 UP 확인
#
# 전제: 스크랩 대상 JVM(gateway:8080/resource-api:8082/pip:8083/pdp:8084)이
#       Windows 호스트에서 bootRun 중이어야 해당 타깃이 UP으로 잡힌다.
#       (관측 스택만 기동하고 싶으면 up-observability.sh 단독 실행)
$ErrorActionPreference = 'Stop'
$distro     = 'Ubuntu-24.04'
$scriptPath = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker/up-observability.sh'

Write-Host '== 관측 스택 기동 (WSL docker) =='
wsl -d $distro -- bash $scriptPath
if ($LASTEXITCODE -ne 0) { throw 'compose up 실패' }

Write-Host ''
Write-Host '== Prometheus 타깃 polling (최대 60s) =='
$want     = @('gateway', 'pdp', 'pip', 'resource-api')
$missing  = $want
$deadline = (Get-Date).AddSeconds(60)
do {
    Start-Sleep -Seconds 3
    try {
        $resp = Invoke-RestMethod -Uri 'http://localhost:9090/api/v1/targets' -TimeoutSec 5
    } catch { continue }
    $active = $resp.data.activeTargets | Where-Object { $_.labels.job -eq 'ztg' }
    $up = @($active | Where-Object { $_.health -eq 'up' } | ForEach-Object { $_.labels.service })
    Write-Host ("  UP: {0}" -f (($up -join ', ')))
    $missing = @($want | Where-Object { $_ -notin $up })
    if ($missing.Count -eq 0) { break }
} while ((Get-Date) -lt $deadline)

Write-Host ''
if ($missing.Count -gt 0) {
    Write-Warning ("DOWN 타깃: {0} — 해당 JVM이 bootRun 중인지 확인하라." -f ($missing -join ', '))
    exit 1
}
Write-Host 'OK: ztg 4개 타깃 모두 UP. 대시보드 -> http://localhost:3000/d/ztg-authz'
