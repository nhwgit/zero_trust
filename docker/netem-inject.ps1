# L4 장애 주입 (tc netem). 대상 컨테이너의 netns에 합류해 eth0에 인위적 지연/지터/손실을 건다.
#
# 왜 이렇게: 앱이 컨테이너라 tc를 호스트에서 못 건다 → 캡처와 같은 방식(--net container:<대상>)으로
#   netshoot를 대상 netns에 합류시키고, qdisc를 바꿀 권한(--cap-add NET_ADMIN)만 더해 tc netem을 건다.
#   netem은 root qdisc라 해당 eth0의 **송신(egress)** 패킷에 적용된다 → 기본 대상 pip의 응답(pip→pdp)이
#   지연/유실되며, 이를 pdp netns 캡처(capture-mtls.ps1)로 보면 pdp↔pip(8083) 링크의 RTT 점프·재전송이 보인다.
#
# 전제: .\docker\up-mtls-docker.ps1 로 컨테이너 스택이 떠 있어야 한다.
# 사용:
#   .\docker\netem-inject.ps1                          # 기본: ztg-pip eth0 ← delay 100ms±20ms, loss 5%
#   .\docker\netem-inject.ps1 -Delay 200ms -Loss 10%   # 더 가혹하게
#   .\docker\netem-inject.ps1 -Target ztg-pdp          # gw→pdp 구간으로 옮겨 걸기
#   .\docker\netem-inject.ps1 -Show                    # 주입 없이 현재 qdisc·드롭 통계만 본다
# 해제: .\docker\netem-clear.ps1
param(
  [string]$Target = 'ztg-pip',     # netns를 빌릴 컨테이너(체인: gateway→pdp→pip)
  [string]$Iface  = 'eth0',
  [string]$Delay  = '100ms',
  [string]$Jitter = '20ms',        # ''(빈 값)이면 지터 없음
  [string]$Loss   = '5%',          # ''(빈 값)이면 손실 없음
  [switch]$Show                    # 주입 대신 현재 qdisc 상태만 출력
)
$ErrorActionPreference = 'Stop'

$distro  = 'Ubuntu-24.04'
$runBase = "docker run --rm --net container:$Target --cap-add NET_ADMIN nicolaka/netshoot"

if ($Show) {
  Write-Host "== 현재 qdisc 상태 ($Target $Iface) ==" -ForegroundColor Cyan
  wsl -d $distro -- bash -c "$runBase tc -s qdisc show dev $Iface"
  exit $LASTEXITCODE
}

# netem 인자 조립 (delay [jitter] [loss N%])
$netem = "delay $Delay"
if ($Jitter) { $netem += " $Jitter" }
if ($Loss)   { $netem += " loss $Loss" }

Write-Host "== netem 주입: $Target $Iface  ←  $netem ==" -ForegroundColor Cyan
Write-Host '   (netshoot 이미지가 없으면 최초 1회 자동 pull — 잠시 걸릴 수 있다)' -ForegroundColor DarkGray

# replace = 멱등(이미 걸려 있어도 'File exists' 없이 덮어쓴다). add는 재실행 시 실패한다.
wsl -d $distro -- bash -c "$runBase tc qdisc replace dev $Iface root netem $netem"
if ($LASTEXITCODE -ne 0) {
  throw "netem 주입 실패 (대상 컨테이너 $Target 가 떠 있는지 확인: wsl -d $distro -- docker ps)"
}

Write-Host ''
Write-Host '주입 확인:' -ForegroundColor Green
wsl -d $distro -- bash -c "$runBase tc -s qdisc show dev $Iface"

Write-Host ''
Write-Host '다음 순서:' -ForegroundColor Yellow
Write-Host '  1) (다른 창) .\docker\capture-mtls.ps1 -OutFile netem-after.pcap   # pdp netns 캡처' -ForegroundColor Gray
Write-Host '  2) k6 또는 smoke로 부하 트리거 -> 캡처에서 재전송/RTT 점프 관찰' -ForegroundColor Gray
Write-Host '  3) 끝나면 .\docker\netem-clear.ps1                                 # qdisc 해제' -ForegroundColor Gray
