# L4 장애 해제 (D2 실습2 — tc netem). netem-inject.ps1로 건 qdisc를 떼어 정상 상태로 되돌린다.
#
# 사용:
#   .\docker\netem-clear.ps1                  # 기본: ztg-pip eth0 의 root qdisc 제거
#   .\docker\netem-clear.ps1 -Target ztg-pdp  # 다른 대상에 걸었으면 같은 대상으로 해제
param(
  [string]$Target = 'ztg-pip',
  [string]$Iface  = 'eth0'
)
$ErrorActionPreference = 'Stop'

$distro  = 'Ubuntu-24.04'
$runBase = "docker run --rm --net container:$Target --cap-add NET_ADMIN nicolaka/netshoot"

Write-Host "== netem 해제: $Target $Iface root qdisc 제거 ==" -ForegroundColor Cyan
# 걸린 게 없으면 'No such file or directory'(exit 2)가 나는데 정상 상태이므로 삼킨다.
wsl -d $distro -- bash -c "$runBase tc qdisc del dev $Iface root 2>/dev/null || true"

Write-Host '해제 후 상태(default qdisc면 정상):' -ForegroundColor Green
wsl -d $distro -- bash -c "$runBase tc qdisc show dev $Iface"
