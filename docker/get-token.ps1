# Keycloak에서 access token을 발급(password grant)받아 claims를 디코딩해 출력 (Windows/PowerShell)
# 사용: ./get-token.ps1 [username] [password]
#   예: ./get-token.ps1 alice alice123
param(
  [string]$User = "alice",
  [string]$Pass = "alice123"
)

$kc     = if ($env:KC)     { $env:KC }     else { "http://localhost:8081" }
$realm  = if ($env:REALM)  { $env:REALM }  else { "ztg" }
$client = if ($env:CLIENT) { $env:CLIENT } else { "ztg-api" }
$secret = if ($env:SECRET) { $env:SECRET } else { "ztg-api-secret" }

$body = @{
  grant_type    = "password"
  client_id     = $client
  client_secret = $secret
  username      = $User
  password      = $Pass
}

try {
  $resp = Invoke-RestMethod -Method Post -Uri "$kc/realms/$realm/protocol/openid-connect/token" -Body $body
} catch {
  Write-Error "토큰 발급 실패 — Keycloak가 떠 있는지($kc) 확인. $_"
  exit 1
}

$token = $resp.access_token
Write-Host "== access_token ==" -ForegroundColor Cyan
Write-Host $token

# JWT payload(두 번째 세그먼트) base64url 디코딩
$payload = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))

Write-Host "`n== payload(claims) ==" -ForegroundColor Cyan
$json | ConvertFrom-Json | ConvertTo-Json -Depth 10
