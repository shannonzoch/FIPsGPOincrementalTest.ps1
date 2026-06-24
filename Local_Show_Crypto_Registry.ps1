#Requires -RunAsAdministrator
###############################################################################
#  Local_Show_Crypto_Registry.ps1
#
#  VERSION : 1.0.0
#
# ─────────────────────────────────────────────────────────────────────────────
#  CHANGE LOG
# ─────────────────────────────────────────────────────────────────────────────
#  v1.0.0  2026-04-22
#    - Initial release.
#    - Read-only display of all SCHANNEL, .NET, and cipher suite registry
#      settings relevant to the SOUR workstation crypto hardening project.
#    - No changes are made to the registry. Safe to run at any time.
#    - Displays expected values alongside actual values for quick comparison.
#    - Covers: AES ciphers, weak ciphers, all protocol Enabled and
#      DisabledByDefault values, all hash algorithms, key exchange algorithms
#      including DH minimum key sizes, .NET SchUseStrongCrypto for all
#      framework versions and bitness paths, configured cipher suite order,
#      and the live active OS TLS cipher suite list.
#
# ─────────────────────────────────────────────────────────────────────────────
#
#  PURPOSE : Display the current local registry state of all cryptography
#            settings managed by the SOUR hardening scripts. Use this to
#            quickly check what is set, what is absent, and whether values
#            match the expected hardened state.
#
#  USAGE   : Run from an elevated PowerShell session on the workstation:
#              .\Show_Crypto_Registry.ps1
#
#            No parameters. No changes made. Read-only.
###############################################################################

$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# ── Helper: read a single registry value safely ───────────────────────────────
function Get-RegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path $Path)) { return $null }
    $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    $raw = $item.GetValue(
        $Name, $null,
        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return $raw
}

# ── Helper: format a value for display ───────────────────────────────────────
function Format-Value {
    param($Value, [string]$Path, [string]$Name)
    if ($null -eq $Value) {
        if (-not (Test-Path $Path)) { return "(key absent — OS default)" }
        return "(value absent — OS default)"
    }
    # Show both decimal and hex for DWord values
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) {
        return "$Value  (0x$('{0:X}' -f [uint64]$Value))"
    }
    return "$Value"
}

# ── Helper: determine status indicator ────────────────────────────────────────
function Get-Status {
    param($Value, $Expected)
    if ($null -eq $Value)    { return "—" }   # absent / OS default
    if ("$Value" -eq "$Expected") { return "✔" }
    return "✘"
}

# ── Section header ────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "████████████████████████████████████████████████████████████████████" -ForegroundColor White
Write-Host "  SOUR Workstation — Crypto Registry State" -ForegroundColor White
Write-Host "  Computer : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  NOTE     : Read-only. No changes are made." -ForegroundColor Green
Write-Host "████████████████████████████████████████████████████████████████████" -ForegroundColor White


###############################################################################
#  SECTION 1 — AES Ciphers
#  Expected: Enabled = 4294967295 (0xFFFFFFFF)
###############################################################################
Write-Section "1. AES Ciphers  (Expected Enabled = 4294967295 / 0xFFFFFFFF)"

$aesResults = foreach ($cipher in @("AES 128/128", "AES 256/256")) {
    $path  = "$base\Ciphers\$cipher"
    $val   = Get-RegValue $path "Enabled"
    [PSCustomObject]@{
        Cipher   = $cipher
        Enabled  = Format-Value $val $path "Enabled"
        Status   = Get-Status $val 4294967295
    }
}
$aesResults | Format-Table -AutoSize


###############################################################################
#  SECTION 2 — Weak Ciphers
#  Expected: Enabled = 0 (explicitly disabled)
###############################################################################
Write-Section "2. Weak Ciphers  (Expected Enabled = 0)"

$weakResults = foreach ($cipher in @(
    "RC4 128/128", "RC4 64/128", "RC4 56/128", "RC4 40/128",
    "RC2 128/128", "RC2 56/128", "RC2 40/128",
    "DES 56/56", "Triple DES 168", "NULL"
)) {
    $path = "$base\Ciphers\$cipher"
    $val  = Get-RegValue $path "Enabled"
    [PSCustomObject]@{
        Cipher   = $cipher
        Enabled  = Format-Value $val $path "Enabled"
        Status   = Get-Status $val 0
    }
}
$weakResults | Format-Table -AutoSize


###############################################################################
#  SECTION 3 — Protocol State
#  Disabled protocols: Enabled = 0, DisabledByDefault = 1
#  Enabled protocols:  Enabled = 1, DisabledByDefault = 0
###############################################################################
Write-Section "3. Protocols  (SSL 2/3 TLS 1.0/1.1: Enabled=0 DBD=1 | TLS 1.2/1.3: Enabled=1 DBD=0)"

$protoResults = foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
    $shouldBeDisabled = $proto -in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")
    foreach ($role in @("Server","Client")) {
        $path    = "$base\Protocols\$proto\$role"
        $enabled = Get-RegValue $path "Enabled"
        $dbd     = Get-RegValue $path "DisabledByDefault"

        $expEnabled = if ($shouldBeDisabled) { 0 } else { 1 }
        $expDBD     = if ($shouldBeDisabled) { 1 } else { 0 }

        [PSCustomObject]@{
            Protocol          = $proto
            Role              = $role
            Enabled           = Format-Value $enabled $path "Enabled"
            "DBD"             = Format-Value $dbd     $path "DisabledByDefault"
            "Enabled OK"      = Get-Status $enabled $expEnabled
            "DBD OK"          = Get-Status $dbd     $expDBD
        }
    }
}
$protoResults | Format-Table -AutoSize


###############################################################################
#  SECTION 4 — Hash Algorithms
#  MD5: Expected Enabled = 0
#  SHA/SHA256/SHA384/SHA512: Expected Enabled = 4294967295 (0xFFFFFFFF)
#  NOTE: SHA256 is intentionally NOT set (known software incompatibility)
###############################################################################
Write-Section "4. Hash Algorithms  (MD5: expect 0 | SHA/SHA384/SHA512: expect 4294967295)"

$hashResults = foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
    $path    = "$base\Hashes\$h"
    $val     = Get-RegValue $path "Enabled"
    $isMd5   = $h -eq "MD5"
    $expVal  = if ($isMd5) { 0 } else { 4294967295 }
    $note    = if ($h -eq "SHA256") { "* intentionally omitted" } else { "" }
    [PSCustomObject]@{
        Hash     = $h
        Enabled  = Format-Value $val $path "Enabled"
        Expected = if ($isMd5) { "0" } else { "4294967295" }
        Status   = if ($h -eq "SHA256") { "—" } else { Get-Status $val $expVal }
        Note     = $note
    }
}
$hashResults | Format-Table -AutoSize

Write-Host "  * SHA256 SCHANNEL hash registry key is intentionally not set" -ForegroundColor DarkGray
Write-Host "    due to confirmed software incompatibility. SHA256 in GCM" -ForegroundColor DarkGray
Write-Host "    cipher suite names is handled by the TLS stack separately." -ForegroundColor DarkGray


###############################################################################
#  SECTION 5 — Key Exchange Algorithms
#  DH and ECDH: Expected Enabled = 4294967295 (0xFFFFFFFF)
#  DH ServerMinKeyBitLength and ClientMinKeyBitLength: Expected = 2048
#  NOTE: PKCS is intentionally NOT set (known software incompatibility)
###############################################################################
Write-Section "5. Key Exchange Algorithms  (DH/ECDH: expect 4294967295 | DH min key: 2048)"

$kxResults = foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
    $path    = "$base\KeyExchangeAlgorithms\$kx"
    $enabled = Get-RegValue $path "Enabled"
    $sMin    = Get-RegValue $path "ServerMinKeyBitLength"
    $cMin    = Get-RegValue $path "ClientMinKeyBitLength"
    $isPKCS  = $kx -eq "PKCS"

    [PSCustomObject]@{
        Algorithm            = $kx
        Enabled              = Format-Value $enabled $path "Enabled"
        "Enabled OK"         = if ($isPKCS) { "— (omitted)" } else { Get-Status $enabled 4294967295 }
        ServerMinKeyBitLen   = if ($null -ne $sMin) { "$sMin" } else { "(not set)" }
        ClientMinKeyBitLen   = if ($null -ne $cMin) { "$cMin" } else { "(not set)" }
        "MinKey OK"          = if ($kx -eq "Diffie-Hellman") {
                                   if ($sMin -eq 2048 -and $cMin -eq 2048) { "✔" }
                                   elseif ($null -eq $sMin -and $null -eq $cMin) { "—" }
                                   else { "✘" }
                               } else { "" }
    }
}
$kxResults | Format-Table -AutoSize

Write-Host "  * PKCS key exchange is intentionally not set due to confirmed" -ForegroundColor DarkGray
Write-Host "    software incompatibility." -ForegroundColor DarkGray


###############################################################################
#  SECTION 6 — .NET Framework SchUseStrongCrypto
#  Expected: 1 for all four paths
###############################################################################
Write-Section "6. .NET Framework SchUseStrongCrypto  (Expected = 1)"

$dotnetResults = foreach ($ver in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @(
        "SOFTWARE\Microsoft\.NETFramework",
        "SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
    )) {
        $path = "HKLM:\$hive\$ver"
        $val  = Get-RegValue $path "SchUseStrongCrypto"
        [PSCustomObject]@{
            Path               = "$hive\$ver"
            SchUseStrongCrypto = Format-Value $val $path "SchUseStrongCrypto"
            Status             = Get-Status $val 1
        }
    }
}
$dotnetResults | Format-Table -AutoSize


###############################################################################
#  SECTION 7 — Cipher Suite Order Policy
#  Set via Local Group Policy / GPO registry path
###############################################################################
Write-Section "7. Cipher Suite Order Policy  (SSL\00010002\Functions)"

$csPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$csVal  = Get-RegValue $csPath "Functions"

if ($null -eq $csVal) {
    Write-Host ""
    Write-Host "  Functions value is NOT SET — Windows OS default cipher order is in use." -ForegroundColor Yellow
    Write-Host "  Path: $csPath" -ForegroundColor DarkGray
} else {
    Write-Host ""
    $i = 0
    $csResults = foreach ($suite in ($csVal -split ",")) {
        $i++
        [PSCustomObject]@{ Order = $i; CipherSuite = $suite.Trim() }
    }
    $csResults | Format-Table -AutoSize
}


###############################################################################
#  SECTION 8 — Live Active TLS Cipher Suites (OS view)
#  This shows what Windows will actually negotiate, accounting for
#  all SCHANNEL settings, the cipher order policy, and OS defaults.
###############################################################################
Write-Section "8. Live Active TLS Cipher Suites (Get-TlsCipherSuite)"

Write-Host ""
$liveSuites = Get-TlsCipherSuite
if ($liveSuites) {
    $i = 0
    $suiteResults = foreach ($s in $liveSuites) {
        $i++
        [PSCustomObject]@{
            Order    = $i
            Suite    = $s.Name
            Exchange = $s.KeyExchangeAlgorithm
            Cipher   = $s.CipherAlgorithm
            Hash     = $s.HashAlgorithm
        }
    }
    $suiteResults | Format-Table -AutoSize
} else {
    Write-Host "  No cipher suites returned by Get-TlsCipherSuite." -ForegroundColor Yellow
}


###############################################################################
#  SECTION 9 — FIPS Algorithm Policy
###############################################################################
Write-Section "9. FIPS Algorithm Policy"

$fipsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
$fipsVal  = Get-RegValue $fipsPath "Enabled"

Write-Host ""
if ($null -eq $fipsVal) {
    Write-Host "  Enabled : (value absent — OS default, treated as 0 / Disabled)" -ForegroundColor Gray
} else {
    $fipsColor = if ($fipsVal -eq 0) { "Green" } else { "Yellow" }
    $fipsLabel = if ($fipsVal -eq 0) { "DISABLED  ✔ (required for software compatibility)" }
                 else                { "ENABLED   ✘ (will cause software incompatibility)" }
    Write-Host "  Enabled : $fipsVal  —  $fipsLabel" -ForegroundColor $fipsColor
}
Write-Host "  Path    : $fipsPath" -ForegroundColor DarkGray


###############################################################################
#  SUMMARY LEGEND
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  STATUS LEGEND" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  ✔  Value matches expected hardened state" -ForegroundColor Green
Write-Host "  ✘  Value present but does not match expected state" -ForegroundColor Red
Write-Host "  —  Value or key absent (Windows OS built-in default applies)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  INTENTIONAL OMISSIONS (known software incompatibilities):" -ForegroundColor DarkGray
Write-Host "    FIPS algorithm policy     — must remain DISABLED" -ForegroundColor DarkGray
Write-Host "    PKCS key exchange         — causes Security Service error" -ForegroundColor DarkGray
Write-Host "    SHA256 SCHANNEL hash key  — causes Security Service error" -ForegroundColor DarkGray
Write-Host ""
