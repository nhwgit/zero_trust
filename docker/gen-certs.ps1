# 서비스간 mTLS용 자체 CA + 서비스 인증서 발급
#
# 왜: gateway↔pdp↔pip 내부 호출을 mTLS로 잠가 "내부망이라 신뢰"를 제거한다(zero-trust).
# 자체(사설) CA 하나로 각 서비스 인증서를 서명하고, 상대 검증용 truststore에는 CA만 담는다.
#
# 산출물(docker/certs/, gitignore — 비밀이므로 비커밋):
#   ca.p12          CA 키+자가서명 인증서 (basicConstraints CA:true)
#   ca.crt          CA 인증서(PEM) — 각 키스토어/트러스트스토어에 주입
#   gateway.p12     gateway 키 + CA가 서명한 인증서 (→pdp 호출 시 클라 인증서)
#   pdp.p12         pdp 키 + CA 서명 인증서 (서버=gw가 검증 / 클라=pip 호출)
#   pip.p12         pip 키 + CA 서명 인증서 (서버=pdp가 검증)
#   truststore.p12  CA 인증서만 — 모든 서비스가 상대 인증서를 이 CA로 검증
#
# 멱등: ca.p12가 이미 있으면 전부 건너뛴다. 다시 만들려면 docker/certs/ 를 지우고 재실행.
# 사용: .\docker\gen-certs.ps1
$ErrorActionPreference = 'Stop'

$certDir = Join-Path $PSScriptRoot 'certs'
$keytool = Join-Path $env:JAVA_HOME 'bin\keytool.exe'
if (-not (Test-Path $keytool)) { throw "keytool 없음: $keytool (JAVA_HOME 확인)" }

# 데모용 정적 비밀번호 — 운영이라면 비밀관리로 주입한다(현 trust-secret과 동일 수준의 데모 비밀).
$storePass = 'ztg-mtls-pass'
$validity  = 3650           # 데모: 10년(회전 데모는 범위 밖)
$keyalg    = 'RSA'
$keysize   = '2048'
# SAN은 서비스별로 구성한다(아래 루프). 컨테이너 네트워크에선 서비스 DNS명(pdp/pip/gateway)으로,
# 호스트 bootRun에선 localhost로 부르므로 둘 다 넣어 양쪽에서 호스트네임 검증이 통과되게 한다.

if (Test-Path (Join-Path $certDir 'ca.p12')) {
  Write-Host "certs/ 이미 존재 — 생성 건너뜀 (재생성하려면 docker/certs/ 삭제 후 재실행)" -ForegroundColor Yellow
  return
}
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

function Kt { & $keytool @args; if ($LASTEXITCODE -ne 0) { throw "keytool 실패: $args" } }

Write-Host '== 1) 자체 CA 생성 ==' -ForegroundColor Cyan
$caP12 = Join-Path $certDir 'ca.p12'
$caCrt = Join-Path $certDir 'ca.crt'
Kt -genkeypair -alias ca -keyalg $keyalg -keysize $keysize -validity $validity `
   -dname 'CN=ztg-internal-ca,O=ztg' -ext 'bc:c' `
   -keystore $caP12 -storetype PKCS12 -storepass $storePass -keypass $storePass
Kt -exportcert -alias ca -rfc -keystore $caP12 -storepass $storePass -file $caCrt

Write-Host '== 2) 서비스 인증서 (CA 서명) ==' -ForegroundColor Cyan
foreach ($svc in 'gateway', 'pdp', 'pip') {
  $p12 = Join-Path $certDir "$svc.p12"
  $csr = Join-Path $certDir "$svc.csr"
  $crt = Join-Path $certDir "$svc.crt"

  # 서비스 DNS명 + localhost 둘 다 SAN에 넣는다(컨테이너=서비스명, 호스트 bootRun=localhost).
  $san = "san=dns:$svc,dns:localhost,ip:127.0.0.1"

  # 서비스 키쌍 → CSR → CA 서명 → (CA + 서명된 인증서) 키스토어에 주입
  Kt -genkeypair -alias $svc -keyalg $keyalg -keysize $keysize -validity $validity `
     -dname "CN=$svc,O=ztg" -ext $san `
     -keystore $p12 -storetype PKCS12 -storepass $storePass -keypass $storePass
  Kt -certreq -alias $svc -keystore $p12 -storepass $storePass -file $csr
  Kt -gencert -alias ca -ext $san -rfc -validity $validity `
     -infile $csr -outfile $crt -keystore $caP12 -storepass $storePass
  # 체인 검증을 위해 CA를 먼저 import(신뢰 앵커), 그다음 서명된 서비스 인증서로 교체
  Kt -importcert -alias ca -noprompt -keystore $p12 -storepass $storePass -file $caCrt
  Kt -importcert -alias $svc -noprompt -keystore $p12 -storepass $storePass -file $crt
  Remove-Item $csr, $crt -ErrorAction SilentlyContinue
  Write-Host "  발급: $svc.p12" -ForegroundColor DarkGray
}

Write-Host '== 3) 공유 truststore (CA만) ==' -ForegroundColor Cyan
$trust = Join-Path $certDir 'truststore.p12'
Kt -importcert -alias ca -noprompt -keystore $trust -storetype PKCS12 -storepass $storePass -file $caCrt

Write-Host "OK: docker/certs/ 에 CA + gateway/pdp/pip 키스토어 + truststore 생성 완료" -ForegroundColor Green
