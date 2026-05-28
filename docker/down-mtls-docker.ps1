# D2 컨테이너 스택 종료 — 앱 4개만 내린다(Keycloak은 다른 스모크에도 쓰이므로 유지).
#   전체 정리(Keycloak 포함)는: wsl -d Ubuntu-24.04 -- bash -c "cd .../docker && docker compose -f docker-compose.yml -f compose-apps.yml down"
$ErrorActionPreference = 'Stop'

$distro      = 'Ubuntu-24.04'
$composeDir  = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker'
$composeArgs = '-f docker-compose.yml -f compose-apps.yml'

Write-Host '== 앱 컨테이너 4개 종료 + WSL keepalive 해제 (keycloak 유지) ==' -ForegroundColor Cyan
wsl -d $distro -- bash -c "cd $composeDir && docker compose $composeArgs rm -sf gateway pdp pip resource-api; pkill -f 'ztg-keepalive' 2>/dev/null; true"
Write-Host 'OK: gateway/pdp/pip/resource-api 컨테이너 제거. (Keycloak은 유지)' -ForegroundColor Green
