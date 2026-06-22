#Requires -RunAsAdministrator
###############################################################################
#  Script 1 of 2 — Disable FIPS + Apply Original Baseline Policies
#
#  PURPOSE: Disables the FIPS flag then applies exactly the policies from
#           your original script. No additional hardening is included here.
#           Run Script 2 separately to test additional recommended policies.
#
#  REBOOT REQUIRED: Yes — SCHANNEL changes are not live until restart.
###############################################################################

$ErrorActionPreference = "Stop"

function Set-RegDWord {
    param([string]$Path, [string]$Name, [int]$Value)
    New-Item -Path $Path -Force | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Host "   SET  $Name = $Value  |  $Path" -ForegroundColor Gray
}

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[1/7] Disabling FIPS Algorithm Policy..." -ForegroundColor Cyan

# Registry (immediate effect for most applications)
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" "Enabled" 0

# secedit INF so the change appears correctly in secpol.msc and survives
# a policy refresh (without this, a secedit /refreshpolicy can re-enable FIPS)
$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
"@
$infPath = "$env:TEMP\DisableFIPS.inf"
$sdbPath = "$env:TEMP\DisableFIPS.sdb"
Set-Content -Path $infPath -Value $infContent -Encoding Unicode
secedit /import /cfg $infPath /db $sdbPath /quiet
secedit /configure /db $sdbPath /cfg $infPath /quiet
Remove-Item $infPath, $sdbPath -Force -ErrorAction SilentlyContinue
Write-Host "   DONE: FIPS disabled via registry and Local Security Policy." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[2/7] Disabling SSL 2.0 and SSL 3.0..." -ForegroundColor Cyan

foreach ($proto in @("SSL 2.0", "SSL 3.0")) {
    foreach ($role in @("Server", "Client")) {
        Set-RegDWord "$schannel\Protocols\$proto\$role" "Enabled" 0
    }
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[3/7] Disabling TLS 1.0 and TLS 1.1..." -ForegroundColor Cyan

foreach ($proto in @("TLS 1.0", "TLS 1.1")) {
    foreach ($role in @("Server", "Client")) {
        Set-RegDWord "$schannel\Protocols\$proto\$role" "Enabled" 0
    }
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[4/7] Enabling TLS 1.2..." -ForegroundColor Cyan

foreach ($role in @("Server", "Client")) {
    Set-RegDWord "$schannel\Protocols\TLS 1.2\$role" "Enabled" 1
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[5/7] Disabling weak ciphers (RC4, DES, 3DES, NULL)..." -ForegroundColor Cyan

foreach ($cipher in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128","DES 56/56","Triple DES 168","NULL")) {
    Set-RegDWord "$schannel\Ciphers\$cipher" "Enabled" 0
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[6/7] Configuring hashes and key exchange algorithms..." -ForegroundColor Cyan

Set-RegDWord "$schannel\Hashes\MD5"    "Enabled" 0
foreach ($hash in @("SHA","SHA256","SHA512")) {
    Set-RegDWord "$schannel\Hashes\$hash" "Enabled" 1
}
foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
    Set-RegDWord "$schannel\KeyExchangeAlgorithms\$kx" "Enabled" 1
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[7/7] Enabling .NET strong crypto (all versions, 32 and 64-bit)..." -ForegroundColor Cyan

foreach ($v in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
        Set-RegDWord "HKLM:\$hive\$v" "SchUseStrongCrypto" 1
    }
}
Write-Host "   DONE." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Baseline complete. Test your software now BEFORE running Script 2." -ForegroundColor Green
Write-Host "  *** A SYSTEM RESTART IS REQUIRED for SCHANNEL changes to apply. ***" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green

$restart = Read-Host "`nRestart now? (Y/N)"
if ($restart -match "^[Yy]$") {
    Write-Host "Restarting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Restart skipped. Reboot before testing." -ForegroundColor Yellow
}
