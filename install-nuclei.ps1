# install-nuclei.ps1
# Jalankan sebagai Administrator:
#   powershell -ExecutionPolicy Bypass -File install-nuclei.ps1
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
if (-not $root) { $root = Get-Location }

Write-Host "[1/4] Whitelist folder di Windows Defender..." -ForegroundColor Cyan
try {
    Add-MpPreference -ExclusionPath $root
    Write-Host "      OK: $root dikecualikan dari Defender" -ForegroundColor Green
} catch {
    Write-Host "      GAGAL tambah exclusion (perlu Administrator): $_" -ForegroundColor Red
    exit 1
}

$version = "v3.11.0"
$zipUrl = "https://github.com/projectdiscovery/nuclei/releases/download/$version/nuclei_3.11.0_windows_amd64.zip"
$tmp = Join-Path $env:TEMP ("nuclei-" + [guid]::NewGuid().ToString())
$zip = Join-Path $tmp "nuclei.zip"

Write-Host "[2/4] Download $version (windows/amd64)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing
} catch {
    Write-Host "      GAGAL download: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[3/4] Extract nuclei.exe ke folder project..." -ForegroundColor Cyan
Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
$src = Join-Path $tmp "nuclei.exe"
$dst = Join-Path $root "nuclei.exe"
Move-Item -LiteralPath $src -Destination $dst -Force
Remove-Item -LiteralPath $tmp -Recurse -Force
Write-Host "      OK: $dst" -ForegroundColor Green

Write-Host "[4/4] Verifikasi..." -ForegroundColor Cyan
& $dst -version
if ($LASTEXITCODE -eq 0) {
    Write-Host "SELESAI. Sekarang jalankan:" -ForegroundColor Green
    Write-Host "  serahkan scan -t https://target.com --profile stealth" -ForegroundColor Yellow
} else {
    Write-Host "Verifikasi gagal (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}
