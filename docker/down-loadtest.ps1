# 부하테스트 스택 종료(핫패스 JVM 4개만)
#
# up-loadtest.ps1로 띄운 bootRun JVM(8080/8082/8083/8084)을 포트로 찾아 종료한다.
# Keycloak(WSL docker)은 다른 스모크에도 쓰이므로 건드리지 않는다.
#   필요하면 수동으로: wsl -d Ubuntu-24.04 -- bash -c "cd /mnt/c/.../docker && docker compose down"
$ErrorActionPreference = 'Stop'

foreach ($port in 8080, 8082, 8083, 8084) {
  $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  foreach ($procId in ($conns.OwningProcess | Select-Object -Unique)) {
    try { Stop-Process -Id $procId -Force; Write-Host "  killed PID $procId (port $port)" -ForegroundColor DarkGray } catch {}
  }
}
Write-Host 'OK: 핫패스 JVM 종료. (Keycloak은 유지)' -ForegroundColor Green
