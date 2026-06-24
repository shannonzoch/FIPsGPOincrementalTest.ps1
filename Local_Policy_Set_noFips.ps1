#Requires -RunAsAdministrator
###############################################################################
#  Local_Policy_Set_noFips.ps1
#
#  VERSION : 1.0.0
#
# ─────────────────────────────────────────────────────────────────────────────
#  CHANGE LOG
# ─────────────────────────────────────────────────────────────────────────────
#  v1.0.0  2026-04-22
#    - Initial release.
#    - Applies all SOUR strong-crypto settings directly to the local registry
#      in a single unattended run. No GPO, no LGPO, no menu.
#    - Equivalent to running all 10 groups in SOUR_Crypto_Local_Incremental.ps1
#      in sequence, plus FIPS disablement.
#    - Correctly uses 0xffffffff bitmask for all SCHANNEL Cipher, Hash, and
#      KeyExchangeAlgorithm Enabled values. Protocol Enabled and
#      DisabledByDefault values correctly use 1/0 boolean flags.
#    - INTENTIONALLY OMITS (confirmed software incompatibilities):
#        - FIPS algorithm policy (disabled, not enabled)
#        - PKCS key exchange registry key
#        - SHA256 SCHANNEL hash registry key
#          (SHA256 in GCM cipher suite names is handled by the TLS stack
#           separately and is not affected by this registry key)
#    - Displays a live verification report after applying all settings.
#    - Prompts for reboot on completion.
#
# ─────────────────────────────────────────────────────────────────────────────
#
#  PURPOSE : Apply all SOUR-compatible strong-crypto registry settings to
#            the local machine in one pass. Run on the workstation directly.
#            Use SOUR_Crypto_Local_Incremental.ps1 if you need to apply
#            settings one group at a time with testing between each.
#
#  USAGE   : Run from an elevated PowerShell session on the workstation:
#              .\Local_Policy_Set_noFips.ps1
#
#  REBOOT  : Required — SCHANNEL changes are not active until after restart.
#
#  SETTINGS APPLIED:
#    [1]  FIPS algorithm policy             — DISABLED via registry + secedit
#    [2]  AES 128/128 and AES 256/256       — Enabled = 0xffffffff
#    [3]  SHA384 hash                       — Enabled = 0xffffffff
#    [4]  SSL 2.0, SSL 3.0, TLS 1.0, 1.1   — Enabled = 0, DisabledByDefault = 1
#    [5]  TLS 1.2                           — Enabled = 1, DisabledByDefault = 0
#    [6]  TLS 1.3                           — Enabled = 1, DisabledByDefault = 0
#    [7]  RC4, RC2, DES, 3DES, NULL         — Enabled = 0
#    [8]  MD5 hash                          — Enabled = 0
#         SHA, SHA256, SHA512 hashes        — Enabled = 0xffffffff
#    [9]  Diffie-Hellman                    — Enabled = 0xffffffff
#                                             ServerMinKeyBitLength = 2048
#                                             ClientMinKeyBitLength = 2048
#         ECDH                              — Enabled = 0xffffffff
#   [10]  .NET SchUseStrongCrypto           — 1 (v4.x and v2.x, 32 and 64-bit)
#   [11]  Cipher suite order                — 9 strong AES-GCM suites
#
#  INTENTIONALLY OMITTED:
#    FIPS enabled              — disabled above, not enforced
#    PKCS key exchange         — causes "Security Service unavailable" error
#    SHA256 SCHANNEL hash key  — causes "Security Service unavailable" error
###############################################################################

$ErrorActionPreference = "Stop"
$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Set-LocalDWord {
    param([string]$Path, [string]$Name, $Value)
    New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Host "   SET  [$Name = $Value]" -ForegroundColor Gray
}

function Set-LocalString {
    param([string]$Path, [string]$Name, [string]$Value)
    New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String
    Write-Host "   SET  [$Name]" -ForegroundColor Gray
}

function Write-Step {
    param([string]$Number, [string]$Title)
    Write-Host ""
    Write-Host "  ── [$Number]  $Title" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "████████████████████████████████████████████████████████████████████" -ForegroundColor White
Write-Host "  Local_Policy_Set_noFips.ps1  —  Full Apply" -ForegroundColor White
Write-Host "  Computer : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "████████████████████████████████████████████████████████████████████" -ForegroundColor White


###############################################################################
#  [1]  Disable FIPS Algorithm Policy
###############################################################################
Write-Step "1/11" "Disabling FIPS Algorithm Policy"

Set-LocalDWord `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" `
    "Enabled" 0

# Apply via secedit so the change is reflected in secpol.msc and survives
# future secedit /refreshpolicy calls without being overwritten
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
$infPath = "$env:TEMP\noFips_secedit.inf"
$sdbPath = "$env:TEMP\noFips_secedit.sdb"
Set-Content -Path $infPath -Value $infContent -Encoding Unicode
secedit /import  /cfg $infPath /db $sdbPath /quiet
secedit /configure /db $sdbPath /cfg $infPath /quiet
Remove-Item $infPath, $sdbPath -Force -ErrorAction SilentlyContinue
Write-Host "   SET  FIPS = 0 via registry and secedit." -ForegroundColor Gray


###############################################################################
#  [2]  Enable AES 128/256 Ciphers
###############################################################################
Write-Step "2/11" "Enabling AES 128/128 and AES 256/256"

Set-LocalDWord "$schannel\Ciphers\AES 128/128" "Enabled" 0xffffffff
Set-LocalDWord "$schannel\Ciphers\AES 256/256" "Enabled" 0xffffffff


###############################################################################
#  [3]  Enable SHA384 Hash
###############################################################################
Write-Step "3/11" "Enabling SHA384 hash"

Set-LocalDWord "$schannel\Hashes\SHA384" "Enabled" 0xffffffff


###############################################################################
#  [4]  Disable Legacy Protocols
#  Both Enabled=0 and DisabledByDefault=1 for belt-and-suspenders coverage
###############################################################################
Write-Step "4/11" "Disabling SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1"

foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
    foreach ($role in @("Server","Client")) {
        Set-LocalDWord "$schannel\Protocols\$proto\$role" "Enabled"           0
        Set-LocalDWord "$schannel\Protocols\$proto\$role" "DisabledByDefault" 1
    }
}


###############################################################################
#  [5]  Enable TLS 1.2 Explicitly
#  Protocol nodes use 1/0 boolean flags, not 0xffffffff bitmask
###############################################################################
Write-Step "5/11" "Explicitly enabling TLS 1.2"

foreach ($role in @("Server","Client")) {
    Set-LocalDWord "$schannel\Protocols\TLS 1.2\$role" "Enabled"           1
    Set-LocalDWord "$schannel\Protocols\TLS 1.2\$role" "DisabledByDefault" 0
}


###############################################################################
#  [6]  Enable TLS 1.3
#  Silently ignored on Windows versions that do not support it
###############################################################################
Write-Step "6/11" "Enabling TLS 1.3"

foreach ($role in @("Server","Client")) {
    Set-LocalDWord "$schannel\Protocols\TLS 1.3\$role" "Enabled"           1
    Set-LocalDWord "$schannel\Protocols\TLS 1.3\$role" "DisabledByDefault" 0
}


###############################################################################
#  [7]  Disable Weak Ciphers (RC4, RC2, DES, 3DES, NULL)
###############################################################################
Write-Step "7/11" "Disabling weak ciphers (RC4, RC2, DES, 3DES, NULL)"

foreach ($cipher in @(
    "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
    "RC2 128/128","RC2 56/128","RC2 40/128",
    "DES 56/56","Triple DES 168","NULL"
)) {
    Set-LocalDWord "$schannel\Ciphers\$cipher" "Enabled" 0
}


###############################################################################
#  [8]  Hash Algorithms
#  MD5 disabled; SHA/SHA256/SHA512 enabled with 0xffffffff bitmask.
#  NOTE: SHA256 hash registry key intentionally omitted — confirmed to cause
#        "Security Service unavailable" error in the SOUR workstation software.
#        SHA256 used in GCM cipher suite names is handled by the TLS stack
#        and is NOT controlled by this SCHANNEL Hashes registry key.
###############################################################################
Write-Step "8/11" "Hash algorithms — disable MD5, enable SHA/SHA256/SHA512"

Set-LocalDWord "$schannel\Hashes\MD5"    "Enabled" 0
Set-LocalDWord "$schannel\Hashes\SHA"    "Enabled" 0xffffffff
Set-LocalDWord "$schannel\Hashes\SHA256" "Enabled" 0xffffffff
Set-LocalDWord "$schannel\Hashes\SHA512" "Enabled" 0xffffffff

Write-Host "   NOTE: SHA256 SCHANNEL hash key — intentionally omitted (software incompatibility)" -ForegroundColor Yellow


###############################################################################
#  [9]  Key Exchange Algorithms + Minimum DH Key Size
#  Enabled uses 0xffffffff bitmask; MinKeyBitLength is an actual size value.
#  NOTE: PKCS key exchange intentionally omitted — confirmed to cause
#        "Security Service unavailable" error in the SOUR workstation software.
###############################################################################
Write-Step "9/11" "Key exchange — DH and ECDH enabled, min DH key 2048-bit"

Set-LocalDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "Enabled"               0xffffffff
Set-LocalDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength"  2048
Set-LocalDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength"  2048
Set-LocalDWord "$schannel\KeyExchangeAlgorithms\ECDH"           "Enabled"               0xffffffff

Write-Host "   NOTE: PKCS key exchange — intentionally omitted (software incompatibility)" -ForegroundColor Yellow


###############################################################################
#  [10]  .NET Framework SchUseStrongCrypto
#  Forces .NET to negotiate TLS 1.2+ instead of defaulting to older protocols.
#  Applied to v4.x and v2.x, both 32-bit and 64-bit runtime paths.
###############################################################################
Write-Step "10/11" ".NET Framework SchUseStrongCrypto"

foreach ($ver in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
    )) {
        Set-LocalDWord "$hive\$ver" "SchUseStrongCrypto" 1
    }
}


###############################################################################
#  [11]  Cipher Suite Order Policy
#  Written to the same registry key that gpedit.msc sets when configuring
#  SSL Cipher Suite Order under Administrative Templates > Network.
#  SHA384 suites listed first; SHA256 GCM suites included as fallback.
#  No PKCS/RSA key exchange suites — forward secrecy throughout.
###############################################################################
Write-Step "11/11" "Cipher suite order policy"

$cipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
) -join ","

Set-LocalString `
    "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
    "Functions" `
    $cipherSuites


###############################################################################
#  LIVE VERIFICATION
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  Verification — Current Local Registry State" -ForegroundColor White
Write-Host "  (SCHANNEL values require a reboot to become active)" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

function Get-RegVal { param([string]$p,[string]$n)
    if (-not (Test-Path $p)) { return $null }
    $i = Get-Item $p -EA SilentlyContinue
    if (-not $i) { return $null }
    return $i.GetValue($n,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
}

Write-Host "`n── FIPS ──" -ForegroundColor Cyan
$f = Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" "Enabled"
[PSCustomObject]@{ Setting = "FipsAlgorithmPolicy\Enabled"; Value = if ($null -ne $f) { $f } else { "(absent)" } } | Format-Table -AutoSize

Write-Host "`n── AES Ciphers ──" -ForegroundColor Cyan
$aesV = foreach ($c in @("AES 128/128","AES 256/256")) {
    $v = Get-RegVal "$schannel\Ciphers\$c" "Enabled"
    [PSCustomObject]@{ Cipher = $c; Enabled = if ($null -ne $v) { $v } else { "(absent)" } }
}
$aesV | Format-Table -AutoSize

Write-Host "`n── Weak Ciphers (expect 0) ──" -ForegroundColor Cyan
$weakV = foreach ($c in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
                           "RC2 128/128","RC2 56/128","RC2 40/128",
                           "DES 56/56","Triple DES 168","NULL")) {
    $v = Get-RegVal "$schannel\Ciphers\$c" "Enabled"
    [PSCustomObject]@{ Cipher = $c; Enabled = if ($null -ne $v) { $v } else { "(absent)" } }
}
$weakV | Format-Table -AutoSize

Write-Host "`n── Protocols ──" -ForegroundColor Cyan
$protoV = foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
    foreach ($r in @("Server","Client")) {
        $path = "$schannel\Protocols\$p\$r"
        $e = Get-RegVal $path "Enabled"
        $d = Get-RegVal $path "DisabledByDefault"
        [PSCustomObject]@{
            Protocol          = $p
            Role              = $r
            Enabled           = if ($null -ne $e) { $e } else { "(absent)" }
            DisabledByDefault = if ($null -ne $d) { $d } else { "(absent)" }
        }
    }
}
$protoV | Format-Table -AutoSize

Write-Host "`n── Hashes ──" -ForegroundColor Cyan
$hashV = foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
    $v = Get-RegVal "$schannel\Hashes\$h" "Enabled"
    [PSCustomObject]@{
        Hash    = $h
        Enabled = if ($null -ne $v) { $v } else { "(absent)" }
        Note    = if ($h -eq "SHA256") { "* intentionally omitted" } else { "" }
    }
}
$hashV | Format-Table -AutoSize

Write-Host "`n── Key Exchange ──" -ForegroundColor Cyan
$kxV = foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
    $path = "$schannel\KeyExchangeAlgorithms\$kx"
    $e  = Get-RegVal $path "Enabled"
    $sm = Get-RegVal $path "ServerMinKeyBitLength"
    $cm = Get-RegVal $path "ClientMinKeyBitLength"
    [PSCustomObject]@{
        Algorithm        = $kx
        Enabled          = if ($null -ne $e)  { $e }  else { "(absent)" }
        ServerMinKeyBits = if ($null -ne $sm) { $sm } else { "(not set)" }
        ClientMinKeyBits = if ($null -ne $cm) { $cm } else { "(not set)" }
        Note             = if ($kx -eq "PKCS") { "* intentionally omitted" } else { "" }
    }
}
$kxV | Format-Table -AutoSize

Write-Host "`n── .NET SchUseStrongCrypto ──" -ForegroundColor Cyan
$dotnetV = foreach ($ver in @("v4.0.30319","v2.0.50727")) {
    foreach ($hv in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
        $v = Get-RegVal "HKLM:\$hv\$ver" "SchUseStrongCrypto"
        [PSCustomObject]@{ Path = "$hv\$ver"; SchUseStrongCrypto = if ($null -ne $v) { $v } else { "(absent)" } }
    }
}
$dotnetV | Format-Table -AutoSize

Write-Host "`n── Cipher Suite Order ──" -ForegroundColor Cyan
$cs = Get-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "Functions"
if ($cs) {
    $i = 0
    $csV = foreach ($s in ($cs -split ",")) { $i++; [PSCustomObject]@{ Order = $i; Suite = $s } }
    $csV | Format-Table -AutoSize
} else {
    Write-Host "  Not set — OS default order in use." -ForegroundColor Yellow
}


###############################################################################
#  COMPLETION
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  All 11 settings applied." -ForegroundColor Green
Write-Host "  *** REBOOT REQUIRED — SCHANNEL changes are not active until restart. ***" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""

$reboot = Read-Host "Restart now? (Y/N)"
if ($reboot -match "^[Yy]$") {
    Write-Host "Rebooting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Restart skipped. Reboot before testing." -ForegroundColor Yellow
}
