#Requires -RunAsAdministrator
###############################################################################
#  ROLLBACK — Reverse Script 1 (Baseline FIPS Disabled)
#
#  PURPOSE: Restores the system to its pre-Script-1 state by:
#             - Re-enabling the FIPS algorithm policy
#             - Removing all SCHANNEL registry keys created by Script 1
#               (removing returns Windows to its built-in defaults, which is
#               safer than guessing what values were there before)
#             - Removing the .NET SchUseStrongCrypto values added by Script 1
#
#  NOTE ON SCHANNEL KEYS: Script 1 created these keys fresh with -Force.
#  Because we cannot know what pre-existed, the correct reversal is to DELETE
#  the keys entirely. A missing SCHANNEL key = Windows uses its built-in
#  defaults for that protocol/cipher, which is the original state.
#
#  REBOOT REQUIRED: Yes — SCHANNEL and FIPS changes are not live until restart.
###############################################################################

$ErrorActionPreference = "Stop"

function Remove-RegKeyIfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force
        Write-Host "   REMOVED  $Path" -ForegroundColor Gray
    } else {
        Write-Host "   SKIPPED  (not present)  $Path" -ForegroundColor DarkGray
    }
}

function Remove-RegValueIfExists {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            Remove-ItemProperty -Path $Path -Name $Name -Force
            Write-Host "   REMOVED  $Name  |  $Path" -ForegroundColor Gray
        } else {
            Write-Host "   SKIPPED  (value not present)  $Name  |  $Path" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "   SKIPPED  (key not present)  $Path" -ForegroundColor DarkGray
    }
}

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[1/7] Re-enabling FIPS Algorithm Policy..." -ForegroundColor Cyan

# Registry
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Value 1 -Type DWord
Write-Host "   SET  Enabled = 1  |  HKLM:\...\FipsAlgorithmPolicy" -ForegroundColor Gray

# secedit — re-applies FIPS=1 into Local Security Policy so secpol.msc
# reflects the change and it survives future policy refreshes
$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,1
"@
$infPath = "$env:TEMP\EnableFIPS.inf"
$sdbPath = "$env:TEMP\EnableFIPS.sdb"
Set-Content -Path $infPath -Value $infContent -Encoding Unicode
secedit /import /cfg $infPath /db $sdbPath /quiet
secedit /configure /db $sdbPath /cfg $infPath /quiet
Remove-Item $infPath, $sdbPath -Force -ErrorAction SilentlyContinue

Write-Host "   DONE: FIPS re-enabled via registry and Local Security Policy." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[2/7] Removing SSL 2.0 and SSL 3.0 protocol keys..." -ForegroundColor Cyan

# Removing the keys returns Windows to its built-in default behaviour.
# Do NOT set Enabled=1 — these protocols should remain off by Windows default
# on any modern OS; we are simply undoing our explicit keys.
foreach ($proto in @("SSL 2.0", "SSL 3.0")) {
    foreach ($role in @("Server", "Client")) {
        Remove-RegKeyIfExists "$schannel\Protocols\$proto\$role"
    }
    # Remove parent key only if now empty
    $parent = "$schannel\Protocols\$proto"
    if ((Test-Path $parent) -and ((Get-ChildItem $parent -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -Path $parent -Force
        Write-Host "   REMOVED  (empty parent)  $parent" -ForegroundColor DarkGray
    }
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[3/7] Removing TLS 1.0 and TLS 1.1 protocol keys..." -ForegroundColor Cyan

foreach ($proto in @("TLS 1.0", "TLS 1.1")) {
    foreach ($role in @("Server", "Client")) {
        Remove-RegKeyIfExists "$schannel\Protocols\$proto\$role"
    }
    $parent = "$schannel\Protocols\$proto"
    if ((Test-Path $parent) -and ((Get-ChildItem $parent -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -Path $parent -Force
        Write-Host "   REMOVED  (empty parent)  $parent" -ForegroundColor DarkGray
    }
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[4/7] Removing TLS 1.2 protocol keys (returns to Windows default)..." -ForegroundColor Cyan

# Script 1 explicitly set TLS 1.2 Enabled=1. Removing the key returns to
# the Windows default (enabled on Win8+/Server 2012+). If your OS had TLS 1.2
# disabled before Script 1 (very unlikely on any supported OS), you would need
# to manually re-disable it — but for all supported Windows versions this
# removal correctly restores the original state.
foreach ($role in @("Server", "Client")) {
    Remove-RegKeyIfExists "$schannel\Protocols\TLS 1.2\$role"
}
$parent = "$schannel\Protocols\TLS 1.2"
if ((Test-Path $parent) -and ((Get-ChildItem $parent -ErrorAction SilentlyContinue).Count -eq 0)) {
    Remove-Item -Path $parent -Force
    Write-Host "   REMOVED  (empty parent)  $parent" -ForegroundColor DarkGray
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[5/7] Removing weak cipher keys (RC4, DES, 3DES, NULL)..." -ForegroundColor Cyan

foreach ($cipher in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128","DES 56/56","Triple DES 168","NULL")) {
    Remove-RegKeyIfExists "$schannel\Ciphers\$cipher"
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[6/7] Removing hash and key exchange algorithm keys..." -ForegroundColor Cyan

foreach ($hash in @("MD5","SHA","SHA256","SHA512")) {
    Remove-RegKeyIfExists "$schannel\Hashes\$hash"
}
foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
    Remove-RegKeyIfExists "$schannel\KeyExchangeAlgorithms\$kx"
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[7/7] Removing .NET SchUseStrongCrypto values..." -ForegroundColor Cyan

foreach ($v in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
        Remove-RegValueIfExists "HKLM:\$hive\$v" "SchUseStrongCrypto"
    }
}
Write-Host "   DONE." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Rollback complete. All Script 1 changes have been reversed." -ForegroundColor Green
Write-Host "  *** A SYSTEM RESTART IS REQUIRED for changes to take effect. ***" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green

$restart = Read-Host "`nRestart now? (Y/N)"
if ($restart -match "^[Yy]$") {
    Write-Host "Restarting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Restart skipped. Reboot before testing." -ForegroundColor Yellow
}
