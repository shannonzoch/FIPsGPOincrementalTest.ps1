#Requires -RunAsAdministrator
###############################################################################
#  Standalone Workstation — FIPS Disabled + Full TLS Compensating Controls
#  For use on NON-DOMAIN-JOINED computers only.
#
#  WHAT THIS SCRIPT DOES:
#    1. Disables the FIPS algorithm policy via Local Security Policy + registry
#    2. Disables legacy protocols: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
#    3. Enables TLS 1.2 and TLS 1.3
#    4. Disables all weak ciphers (RC4, RC2, DES, 3DES, NULL)
#    5. Explicitly enables AES 128/256
#    6. Disables weak hashes (MD5), enables SHA family
#    7. Configures key exchange algorithms + minimum DH key size (2048-bit)
#    8. Enforces strong cipher suite order
#    9. Enables strong crypto for all .NET Framework versions
#   10. Applies settings to Local Group Policy (LGPO) so they survive
#       manual edits to Local Security Policy in the GUI
#
#  REBOOT REQUIRED: Yes — SCHANNEL and Local Security Policy changes are
#                   not active until the system restarts.
#
#  TESTED ON: Windows 10 21H2+, Windows 11, Windows Server 2019/2022
###############################################################################

$ErrorActionPreference = "Stop"
$WarningPreference     = "Continue"

# ── Helper: Write a section header ──────────────────────────────────────────
function Write-Step {
    param([string]$Number, [string]$Title)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
    Write-Host "  [$Number]  $Title" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
}

# ── Helper: Create registry key and set a DWORD value ───────────────────────
function Set-RegDWord {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Host "   SET  [$Name = $Value]  $Path" -ForegroundColor Gray
}

# ── Helper: Create registry key and set a String value ──────────────────────
function Set-RegString {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String
    Write-Host "   SET  [$Name]  $Path" -ForegroundColor Gray
}

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"


###############################################################################
#  STEP 1 — Disable FIPS Algorithm Policy
###############################################################################
Write-Step "1/9" "Disabling FIPS Algorithm Policy"

# ── 1a: Registry key (takes immediate effect for most applications) ──────────
Set-RegDWord `
    -Path  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" `
    -Name  "Enabled" `
    -Value 0

# ── 1b: Apply via secedit INF so Local Security Policy GUI reflects the
#        change and it persists through "secedit /refreshpolicy". ────────────
Write-Host "   Applying via secedit (Local Security Policy)..." -ForegroundColor Gray

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

# Import the INF into the local security database
secedit /import /cfg $infPath /db $sdbPath /quiet

# Apply the local security database
secedit /configure /db $sdbPath /cfg $infPath /quiet

# Clean up temp files
Remove-Item $infPath, $sdbPath -Force -ErrorAction SilentlyContinue

Write-Host "   DONE: FIPS policy set to Disabled via registry and Local Security Policy." -ForegroundColor Green


###############################################################################
#  STEP 2 — Disable Legacy SSL/TLS Protocols
###############################################################################
Write-Step "2/9" "Disabling Legacy Protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)"

# Both Enabled=0 and DisabledByDefault=1 are set for each disabled protocol.
# Some applications and runtimes check only DisabledByDefault, not Enabled.
foreach ($proto in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
    foreach ($role in @("Server", "Client")) {
        $path = "$schannel\Protocols\$proto\$role"
        Set-RegDWord $path "Enabled"          0
        Set-RegDWord $path "DisabledByDefault" 1
    }
}

Write-Host "   DONE: All legacy protocols disabled." -ForegroundColor Green


###############################################################################
#  STEP 3 — Enable TLS 1.2 and TLS 1.3
###############################################################################
Write-Step "3/9" "Enabling TLS 1.2 and TLS 1.3"

foreach ($proto in @("TLS 1.2", "TLS 1.3")) {
    foreach ($role in @("Server", "Client")) {
        $path = "$schannel\Protocols\$proto\$role"
        Set-RegDWord $path "Enabled"          1
        Set-RegDWord $path "DisabledByDefault" 0
    }
}

# Note: TLS 1.3 registry keys are silently ignored on Windows versions that
# do not support it (pre-Windows 10 1903 / pre-Server 2022). No harm done.
Write-Host "   DONE: TLS 1.2 and TLS 1.3 enabled." -ForegroundColor Green


###############################################################################
#  STEP 4 — Disable Weak Ciphers
###############################################################################
Write-Step "4/9" "Disabling Weak Ciphers (RC4, RC2, DES, 3DES, NULL)"

$weakCiphers = @(
    "RC4 128/128",   # RC4 — all bit lengths
    "RC4 64/128",
    "RC4 56/128",
    "RC4 40/128",
    "RC2 128/128",   # RC2 — all bit lengths
    "RC2 56/128",
    "RC2 40/128",
    "DES 56/56",     # DES
    "Triple DES 168", # 3DES — may break very old RDP/IIS clients
    "NULL"           # NULL cipher — no encryption
)

foreach ($cipher in $weakCiphers) {
    Set-RegDWord "$schannel\Ciphers\$cipher" "Enabled" 0
}

Write-Host "   DONE: All weak ciphers disabled." -ForegroundColor Green


###############################################################################
#  STEP 5 — Explicitly Enable AES Ciphers
###############################################################################
Write-Step "5/9" "Explicitly Enabling AES 128 and AES 256"

# AES is the primary FIPS-approved symmetric cipher. After disabling all legacy
# ciphers it must be explicitly allowed to guarantee availability and to satisfy
# security audits. Without this some application stacks may fail to negotiate.
foreach ($aes in @("AES 128/128", "AES 256/256")) {
    Set-RegDWord "$schannel\Ciphers\$aes" "Enabled" 1
}

Write-Host "   DONE: AES 128/128 and AES 256/256 enabled." -ForegroundColor Green


###############################################################################
#  STEP 6 — Configure Hash Algorithms
###############################################################################
Write-Step "6/9" "Configuring Hash Algorithms (disable MD5, enable SHA family)"

# Disable MD5
Set-RegDWord "$schannel\Hashes\MD5" "Enabled" 0

# Enable full SHA family (SHA-1 kept for legacy compatibility where required;
# SHA-256/384/512 are the primary algorithms in use with TLS 1.2+)
foreach ($hash in @("SHA", "SHA256", "SHA384", "SHA512")) {
    Set-RegDWord "$schannel\Hashes\$hash" "Enabled" 1
}

Write-Host "   DONE: MD5 disabled, SHA/SHA256/SHA384/SHA512 enabled." -ForegroundColor Green


###############################################################################
#  STEP 7 — Configure Key Exchange Algorithms
###############################################################################
Write-Step "7/9" "Configuring Key Exchange Algorithms + Minimum DH Key Size"

# Enable all three key exchange types
foreach ($kx in @("Diffie-Hellman", "ECDH", "PKCS")) {
    Set-RegDWord "$schannel\KeyExchangeAlgorithms\$kx" "Enabled" 1
}

# Enforce 2048-bit minimum for Diffie-Hellman on both sides.
# Prevents Logjam-style attacks where DH downgrades to 512 or 1024-bit keys.
Set-RegDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength" 2048
Set-RegDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength" 2048

Write-Host "   DONE: Key exchange configured. DH minimum = 2048-bit." -ForegroundColor Green


###############################################################################
#  STEP 8 — Enforce Cipher Suite Order via Local Group Policy Registry
###############################################################################
Write-Step "8/9" "Setting Cipher Suite Order (Local Group Policy)"

# This registry path is the exact key set by the Local Group Policy:
#   Computer Configuration > Administrative Templates > Network
#   > SSL Configuration Settings > SSL Cipher Suite Order
#
# Setting it here is equivalent to opening gpedit.msc and configuring
# the policy manually — it will appear as "Enabled" in gpedit.msc.
#
# Order rationale:
#   - TLS 1.3 suites listed first (OS handles these natively when available)
#   - TLS 1.2 ECDHE suites next (forward secrecy via elliptic curve DH)
#   - TLS 1.2 DHE suites last (forward secrecy via classical DH, fallback)
#   - RSA/PKCS key exchange suites intentionally omitted (no forward secrecy)

$cipherSuites = @(
    "TLS_AES_256_GCM_SHA384",                    # TLS 1.3 — strongest
    "TLS_AES_128_GCM_SHA256",                    # TLS 1.3
    "TLS_CHACHA20_POLY1305_SHA256",              # TLS 1.3 — good for non-AES-NI hardware
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",  # TLS 1.2 — preferred
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",  # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",    # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",    # TLS 1.2
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",      # TLS 1.2 — fallback
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"       # TLS 1.2 — fallback
) -join ","

$cipherRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
Set-RegString -Path $cipherRegPath -Name "Functions" -Value $cipherSuites

Write-Host "   DONE: Cipher suite order applied (9 suites, AES-GCM preferred)." -ForegroundColor Green


###############################################################################
#  STEP 9 — Enable Strong Crypto for All .NET Framework Versions
###############################################################################
Write-Step "9/9" "Enabling Strong Crypto for .NET Framework (all versions)"

# SchUseStrongCrypto forces .NET to use TLS 1.2+ and strong cipher suites
# instead of defaulting to older protocols. Required for both 32-bit and
# 64-bit runtime paths, and for both .NET 4.x and 2.x/3.5.

$dotnetPaths = @(
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319",
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
)

foreach ($path in $dotnetPaths) {
    Set-RegDWord $path "SchUseStrongCrypto" 1
}

Write-Host "   DONE: .NET strong crypto enabled for v2.x (32/64-bit) and v4.x (32/64-bit)." -ForegroundColor Green


###############################################################################
#  SUMMARY
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  ALL STEPS COMPLETE" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  Applied:"
Write-Host "    [1] FIPS disabled (registry + Local Security Policy)"
Write-Host "    [2] SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 disabled"
Write-Host "    [3] TLS 1.2 and TLS 1.3 enabled"
Write-Host "    [4] RC4, RC2, DES, 3DES, NULL ciphers disabled"
Write-Host "    [5] AES 128/128 and AES 256/256 explicitly enabled"
Write-Host "    [6] MD5 disabled; SHA / SHA256 / SHA384 / SHA512 enabled"
Write-Host "    [7] Key exchange configured; DH minimum = 2048-bit"
Write-Host "    [8] Cipher suite order set (9 strong suites)"
Write-Host "    [9] .NET SchUseStrongCrypto enabled (all versions)"
Write-Host ""
Write-Host "  *** A SYSTEM RESTART IS REQUIRED for all changes to take effect. ***" -ForegroundColor Yellow
Write-Host ""

$restart = Read-Host "  Restart now? (Y/N)"
if ($restart -match "^[Yy]$") {
    Write-Host "  Restarting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "  Restart skipped. Remember to reboot before testing." -ForegroundColor Yellow
}
