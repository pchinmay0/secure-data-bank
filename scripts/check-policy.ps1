# Runs the authorization matrix against the live API.
#
#   powershell -ExecutionPolicy Bypass -File scripts\check-policy.ps1
#
# Reads DATABANK_CLIENT_SECRET and DEV_USER_PASSWORD from .env, or pass
# -Password explicitly. Dev use only.
param(
    [string]$Password,
    [string]$Api = "http://localhost:8000",
    [string]$Keycloak = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

function Get-EnvValue($key) {
    $line = Get-Content .env | Where-Object { $_ -like "$key=*" }
    if (-not $line) { return $null }
    return $line.Substring("$key=".Length).Trim()
}

$secret = Get-EnvValue 'DATABANK_CLIENT_SECRET'
if (-not $Password) { $Password = Get-EnvValue 'DEV_USER_PASSWORD' }
if (-not $Password) {
    Write-Host "No password given and DEV_USER_PASSWORD is not in .env" -ForegroundColor Red
    exit 1
}

$tokens = @{}
foreach ($u in 'alice', 'arun', 'bob', 'priya') {
    $resp = curl.exe -s -X POST "$Keycloak/realms/databank/protocol/openid-connect/token" `
        -d "client_id=databank-api" -d "client_secret=$secret" `
        -d "grant_type=password" -d "username=$u" -d "password=$Password" | ConvertFrom-Json
    if (-not $resp.access_token) {
        Write-Host "could not get a token for $u" -ForegroundColor Red
        exit 1
    }
    $tokens[$u] = $resp.access_token
}

# user, path, expected status, what it demonstrates
$cases = @(
    @('alice', '/datasets/4',      200, 'public dataset, metadata'),
    @('alice', '/datasets/4/file', 200, 'public dataset, download'),
    @('bob',   '/datasets/4/file', 200, 'public is cross-institution'),
    @('alice', '/datasets/6',      200, 'own institution, restricted metadata'),
    @('alice', '/datasets/6/file', 403, 'RESEARCHER DENIED restricted download'),
    @('arun',  '/datasets/6/file', 200, 'STEWARD ALLOWED same download'),
    @('bob',   '/datasets/6',      404, 'other institution, not shared: hidden'),
    @('bob',   '/datasets/1',      200, 'shared with LabB: metadata visible'),
    @('bob',   '/datasets/1/file', 403, 'shared grants metadata, never the file'),
    @('priya', '/datasets/6/file', 404, 'admin has NO cross-institution power'),
    @('priya', '/datasets/9/file', 200, 'admin downloads own restricted data'),
    @('bob',   '/datasets/9/file', 403, 'researcher denied own restricted download')
)

$pass = 0
$fail = 0
foreach ($c in $cases) {
    $user, $path, $expected, $note = $c
    $code = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $($tokens[$user])" "$Api$path"
    if ([int]$code -eq $expected) {
        $pass++
        Write-Host ("PASS  {0,-6} {1,-18} {2}  {3}" -f $user, $path, $code, $note) -ForegroundColor Green
    }
    else {
        $fail++
        Write-Host ("FAIL  {0,-6} {1,-18} {2} (expected {3})  {4}" -f $user, $path, $code, $expected, $note) -ForegroundColor Red
    }
}

# No token at all must never work
$code = curl.exe -s -o NUL -w "%{http_code}" "$Api/datasets/4"
if ([int]$code -eq 401) { $pass++; Write-Host ("PASS  {0,-6} {1,-18} {2}  no token" -f '-', '/datasets/4', $code) -ForegroundColor Green }
else { $fail++; Write-Host ("FAIL  no token gave {0}, expected 401" -f $code) -ForegroundColor Red }

Write-Host ""
Write-Host "$pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
