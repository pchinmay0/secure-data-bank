# Anchors the audit log: records the current tip hash OUTSIDE the database.
#
#   powershell -ExecutionPolicy Bypass -File scripts\anchor.ps1
#
# A hash chain proves internal consistency and signatures prove authenticity,
# but neither detects TRUNCATION: delete the newest entries and what remains
# still links and verifies. An anchor is a copy of the tip hash kept somewhere
# the database cannot reach. If the log is later shorter than the anchor, or
# the anchored hash no longer appears in it, entries were removed.
#
# Here the anchor file is committed to Git, so the record lives in a second
# system with its own history. In production you would push it somewhere an
# attacker with database access has no write path to: object storage with a
# retention lock, a transparency log, or a different account entirely.
param(
    [string]$Api = "http://localhost:8000",
    [string]$Keycloak = "http://localhost:8080",
    [string]$AnchorFile = "audit-anchors.txt",
    [string]$User = "priya"
)

$ErrorActionPreference = "Stop"

function Get-EnvValue($key) {
    $line = Get-Content .env | Where-Object { $_ -like "$key=*" }
    if (-not $line) { throw "$key is not set in .env" }
    return $line.Substring("$key=".Length).Trim()
}

$secret = Get-EnvValue 'DATABANK_CLIENT_SECRET'
$password = Get-EnvValue 'DEV_USER_PASSWORD'

$token = (curl.exe -s -X POST "$Keycloak/realms/databank/protocol/openid-connect/token" `
        -d "client_id=databank-api" -d "client_secret=$secret" `
        -d "grant_type=password" -d "username=$User" -d "password=$password" |
    ConvertFrom-Json).access_token

if (-not $token) { throw "could not get a token for $User" }

$result = curl.exe -s -H "Authorization: Bearer $token" "$Api/audit/verify" | ConvertFrom-Json

if (-not $result.ok) {
    Write-Host "REFUSING TO ANCHOR: the log does not verify." -ForegroundColor Red
    Write-Host ("  first bad entry: {0}  reason: {1}" -f $result.first_bad_id, $result.reason)
    exit 1
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$line = "{0} entries={1} tip={2}" -f $stamp, $result.entries_checked, $result.tip_hash

if (-not (Test-Path $AnchorFile)) {
    Set-Content -Path $AnchorFile -Value "# Audit log anchors. Append-only. Commit each new line." -Encoding ascii
}
Add-Content -Path $AnchorFile -Value $line -Encoding ascii

Write-Host "anchored: $line" -ForegroundColor Green
Write-Host "commit $AnchorFile so the anchor lives outside this machine's database."
