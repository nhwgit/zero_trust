# 서비스간 mTLS 패킷 캡처. pdp 컨테이너의 네트워크 네임스페이스에 tcpdump 사이드카를 붙여
# 들어오는(gateway→pdp:8084) + 나가는(pdp→pip:8083) mTLS 트래픽을 한 번에 잡는다.
#
# 전제: .\docker\up-mtls-docker.ps1 로 컨테이너 스택이 떠 있어야 한다.
# 흐름: 이 스크립트로 캡처 시작(N초) → 그 사이 다른 창에서 .\docker\smoke-mtls.ps1 로 트리거 → 자동 종료.
# 산출물: docs/packet-study/mtls.pcap  (Wireshark/tshark로 분석 — 핵심은 사용자가 직접 와이어를 보는 것)
#
# 사용: .\docker\capture-mtls.ps1 [-Seconds 25] [-OutFile mtls.pcap]
param(
  [int]$Seconds = 25,
  [string]$OutFile = 'mtls.pcap'
)
$ErrorActionPreference = 'Stop'

$distro     = 'Ubuntu-24.04'
$composeDir = '/mnt/c/Users/USER/Desktop/nhw/project/keycloak/docker'
$outPath    = "../docs/packet-study/$OutFile"

Write-Host "== tcpdump 캡처 (pdp netns, ${Seconds}s) → docs/packet-study/$OutFile ==" -ForegroundColor Cyan
Write-Host '   지금 다른 PowerShell 창에서  .\docker\smoke-mtls.ps1  을 실행해 핸드셰이크를 트리거하라.' -ForegroundColor Yellow
Write-Host '   (netshoot 이미지가 없으면 최초 1회 자동 pull — 잠시 걸릴 수 있다)' -ForegroundColor DarkGray

# timeout이 tcpdump를 끝내면 exit 124 → 정상 종료로 간주(throw 금지).
$cmd = "cd $composeDir && mkdir -p ../docs/packet-study && " +
       "docker run --rm --net container:ztg-pdp nicolaka/netshoot " +
       "timeout $Seconds tcpdump -i any -U -w - 'tcp port 8084 or tcp port 8083' > $outPath"
wsl -d $distro -- bash -c $cmd

Write-Host ''
Write-Host "OK: docs/packet-study/$OutFile 저장. 분석 필터(이것부터):" -ForegroundColor Green
Write-Host '  tls.handshake.type == 1   ClientHello' -ForegroundColor Gray
Write-Host '  tls.handshake.type == 11  Certificate (서버 CN=pdp / 클라 CN=gateway 가 보인다)' -ForegroundColor Gray
Write-Host '  tls.handshake.type == 13  CertificateRequest  ← mTLS 입증의 결정적 한 컷(단방향 TLS엔 없음)' -ForegroundColor Gray
Write-Host '  tcp.port == 8084 / 8083   mTLS 데이터 구간(핸드셰이크 후 Application Data=암호문)' -ForegroundColor Gray
Write-Host '  tshark -r docs/packet-study/mtls.pcap -Y "tls.handshake" 텍스트를 붙여 공동 해석 가능.' -ForegroundColor DarkGray
