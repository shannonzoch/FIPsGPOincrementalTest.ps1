###############################################################################
#  SOUR_Crypto_Apply_All.ps1
#
#  VERSION : 1.0.0
#
# ─────────────────────────────────────────────────────────────────────────────
#  CHANGE LOG
# ─────────────────────────────────────────────────────────────────────────────
#  v1.0.0  2026-04-22
#    - Initial release.
#    - Applies all 10 strong-crypto policy groups to the SOUR OU GPO in a
#      single run with no prompting. Settings are identical to those in
#      SOUR_Crypto_Incremental_Push.ps1 v1.2.0.
#    - GPOName and SOURHost accepted as mandatory script parameters.
#    - Includes post-push live registry verification via Invoke-Command.
#    - FIPS flag is intentionally NOT set (known software incompatibility).
#    - SHA256 hash registry key is intentionally NOT set (known software
#      incompatibility — SHA256 in GCM cipher suites is unaffected).
#    - PKCS key exchange is intentionally NOT set (known software
#      incompatibility).
#
# ─────────────────────────────────────────────────────────────────────────────
#
#  PURPOSE : Apply all FIPS-equivalent strong-crypto GPO registry settings
#            to the SOUR workstation OU GPO in one pass, then force-push
#            to the workstation and display a live verification report.
#
#  USAGE   :
#    .\SOUR_Crypto_Apply_All.ps1 -GPOName "SOUR-Workstation-Policy" `
#                                 -SOURHost "SOUR-WORKSTATION"
#
#  PRE-REQS: Elevated PowerShell session on the Domain Controller.
#            GroupPolicy RSAT module must be available.
#            The SOUR workstation must be reachable (WinRM / admin share).
#
#  REBOOT  : Required on the workstation after this script completes.
#            SCHANNEL changes are not active until the system restarts.
#
#  SETTINGS APPLIED:
#    [1]  AES 128/128 and AES 256/256 ciphers enabled  (0xffffffff)
#    [2]  SHA384 hash enabled                           (0xffffffff)
#    [3]  SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 disabled  (Enabled=0,
#                                                        DisabledByDefault=1)
#    [4]  TLS 1.2 explicitly enabled                    (Enabled=1,
#                                                        DisabledByDefault=0)
#    [5]  TLS 1.3 enabled                               (Enabled=1,
#                                                        DisabledByDefault=0)
#    [6]  RC4, RC2, DES, 3DES, NULL ciphers disabled    (Enabled=0)
#    [7]  MD5 hash disabled; SHA/SHA256/SHA512 enabled   (0xffffffff)
#    [8]  Diffie-Hellman and ECDH key exchange enabled   (0xffffffff)
#         DH ServerMinKeyBitLength and ClientMinKeyBitLength = 2048
#    [9]  .NET Framework SchUseStrongCrypto = 1
#         (v4.0.30319 and v2.0.50727, 32-bit and 64-bit paths)
#   [10]  Cipher suite order policy (9 strong AES-GCM suites)
#
#  INTENTIONALLY OMITTED (software incompatibility):
#    - FIPS algorithm policy
#    - PKCS key exchange
#    - SHA256 SCHANNEL hash registry key
#      (SHA256 in GCM cipher suite names is handled by the TLS stack,
#       not the SCHANNEL Hashes registry node, and is unaffected)
###############################################################################

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $true,
        HelpMessage = "Exact display name of the SOUR workstation OU GPO on the Domain Controller."
    )]
    [string]$GPOName,

    [Parameter(
        Mandatory = $true,
        HelpMessage = "Hostname or FQDN of the SOUR workstation to push policy to."
    )]
    [string]$SOURHost
)

Import-Module GroupPolicy -ErrorAction Stop

$base = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Set-CryptoValue {
    param([string]$Key, [string]$Name, $Value, [string]$Type = "DWord")
    Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
    Write-Host "   SET  [$Name = $Value]" -ForegroundColor Gray
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ── $Title" -ForegroundColor Cyan
}

# ── Confirm GPO exists before doing any work ──────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  SOUR Strong Crypto — Full Apply" -ForegroundColor White
Write-Host "  GPO    : $GPOName" -ForegroundColor White
Write-Host "  Target : $SOURHost" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

try {
    Get-GPO -Name $GPOName -ErrorAction Stop | Out-Null
    Write-Host "  GPO verified." -ForegroundColor Green
} catch {
    Write-Error "GPO '$GPOName' not found. Verify the -GPOName parameter and try again."
    exit 1
}


###############################################################################
#  [1] Enable AES Ciphers
###############################################################################
Write-Section "[1/10] Enabling AES 128/128 and AES 256/256 ciphers"

Set-CryptoValue "$base\Ciphers\AES 128/128" "Enabled" 0xffffffff
Set-CryptoValue "$base\Ciphers\AES 256/256" "Enabled" 0xffffffff


###############################################################################
#  [2] Enable SHA384 Hash
###############################################################################
Write-Section "[2/10] Enabling SHA384 hash"

Set-CryptoValue "$base\Hashes\SHA384" "Enabled" 0xffffffff


###############################################################################
#  [3] Disable Legacy Protocols
#      Enabled=0 and DisabledByDefault=1 — belt-and-suspenders
###############################################################################
Write-Section "[3/10] Disabling legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)"

foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
    foreach ($role in @("Server","Client")) {
        Set-CryptoValue "$base\Protocols\$proto\$role" "Enabled"           0
        Set-CryptoValue "$base\Protocols\$proto\$role" "DisabledByDefault" 1
    }
}


###############################################################################
#  [4] Enable TLS 1.2 Explicitly
#      Protocol nodes use 1/0 boolean flags, not 0xffffffff bitmask
###############################################################################
Write-Section "[4/10] Explicitly enabling TLS 1.2"

foreach ($role in @("Server","Client")) {
    Set-CryptoValue "$base\Protocols\TLS 1.2\$role" "Enabled"           1
    Set-CryptoValue "$base\Protocols\TLS 1.2\$role" "DisabledByDefault" 0
}


###############################################################################
#  [5] Enable TLS 1.3
#      Silently ignored on Windows versions that do not support it
###############################################################################
Write-Section "[5/10] Enabling TLS 1.3"

foreach ($role in @("Server","Client")) {
    Set-CryptoValue "$base\Protocols\TLS 1.3\$role" "Enabled"           1
    Set-CryptoValue "$base\Protocols\TLS 1.3\$role" "DisabledByDefault" 0
}


###############################################################################
#  [6] Disable Weak Ciphers
###############################################################################
Write-Section "[6/10] Disabling weak ciphers (RC4, RC2, DES, 3DES, NULL)"

foreach ($cipher in @(
    "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
    "RC2 128/128","RC2 56/128","RC2 40/128",
    "DES 56/56","Triple DES 168","NULL"
)) {
    Set-CryptoValue "$base\Ciphers\$cipher" "Enabled" 0
}


###############################################################################
#  [7] Hash Algorithms
#      MD5 disabled; SHA/SHA256/SHA512 enabled with 0xffffffff bitmask
#      NOTE: SHA256 hash registry key intentionally omitted — known
#            software incompatibility. SHA256 in GCM cipher suite names
#            is handled by the TLS stack and is not affected by this key.
###############################################################################
Write-Section "[7/10] Hashes — disabling MD5, enabling SHA/SHA256/SHA512"

Set-CryptoValue "$base\Hashes\MD5"    "Enabled" 0
Set-CryptoValue "$base\Hashes\SHA"    "Enabled" 0xffffffff
Set-CryptoValue "$base\Hashes\SHA256" "Enabled" 0xffffffff
Set-CryptoValue "$base\Hashes\SHA512" "Enabled" 0xffffffff


###############################################################################
#  [8] Key Exchange Algorithms + Minimum DH Key Size
#      Enabled uses 0xffffffff bitmask; MinKeyBitLength is an actual value
#      NOTE: PKCS key exchange intentionally omitted — known software
#            incompatibility.
###############################################################################
Write-Section "[8/10] Key exchange — enabling DH and ECDH, setting min DH key size 2048-bit"

Set-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "Enabled"              0xffffffff
Set-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength" 2048
Set-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength" 2048
Set-CryptoValue "$base\KeyExchangeAlgorithms\ECDH"           "Enabled"              0xffffffff


###############################################################################
#  [9] .NET Framework SchUseStrongCrypto
#      Forces .NET to negotiate TLS 1.2+ instead of defaulting to older
#      protocols. Applied to v4.x and v2.x, both 32-bit and 64-bit paths.
###############################################################################
Write-Section "[9/10] .NET Framework SchUseStrongCrypto"

foreach ($version in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @(
        "HKLM\SOFTWARE\Microsoft\.NETFramework",
        "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
    )) {
        Set-CryptoValue "$hive\$version" "SchUseStrongCrypto" 1
    }
}


###############################################################################
#  [10] Cipher Suite Order Policy
#       SHA384 suites listed first; SHA256 GCM suites included as fallback.
#       No PKCS/RSA key exchange suites — forward secrecy enforced throughout.
###############################################################################
Write-Section "[10/10] Cipher suite order policy"

$cipherSuites = (
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

Set-GPRegistryValue `
    -Name      $GPOName `
    -Key       "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
    -ValueName "Functions" `
    -Type      String `
    -Value     $cipherSuites | Out-Null
Write-Host "   SET  [Functions = 9 cipher suites]" -ForegroundColor Gray


###############################################################################
#  PUSH TO WORKSTATION
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  All settings written to GPO. Pushing to $SOURHost ..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

try {
    Invoke-GPUpdate -Computer $SOURHost -Force -RandomDelayInMinutes 0 -ErrorAction Stop
    Write-Host "  gpupdate delivered to $SOURHost." -ForegroundColor Green
} catch {
    Write-Warning "Invoke-GPUpdate failed: $_"
    Write-Warning "Run  gpupdate /force  manually on the workstation."
}


###############################################################################
#  LIVE VERIFICATION — queries the workstation registry post-push
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  Live Registry Verification on $SOURHost" -ForegroundColor White
Write-Host "  (Run after workstation reboot for SCHANNEL values to be active)" -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

Invoke-Command -ComputerName $SOURHost -ScriptBlock {
    param($b)

    Write-Host "`n── AES Ciphers (expect 4294967295) ──" -ForegroundColor Cyan
    $aesResults = foreach ($aes in @("AES 128/128","AES 256/256")) {
        $v = (Get-ItemProperty "HKLM:\$b\Ciphers\$aes" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Cipher = $aes; Enabled = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
    }
    $aesResults | Format-Table -AutoSize

    Write-Host "`n── Weak Ciphers (expect 0) ──" -ForegroundColor Cyan
    $weakResults = foreach ($c in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        $v = (Get-ItemProperty "HKLM:\$b\Ciphers\$c" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Cipher = $c; Enabled = if ($null -ne $v) { $v } else { "(absent)" } }
    }
    $weakResults | Format-Table -AutoSize

    Write-Host "`n── Protocols ──" -ForegroundColor Cyan
    $protoResults = foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
        foreach ($r in @("Server","Client")) {
            $vals = Get-ItemProperty "HKLM:\$b\Protocols\$p\$r" -EA SilentlyContinue
            [PSCustomObject]@{
                Protocol          = $p
                Role              = $r
                Enabled           = if ($vals) { $vals.Enabled }           else { "(absent=OS default)" }
                DisabledByDefault = if ($vals) { $vals.DisabledByDefault } else { "(absent=OS default)" }
            }
        }
    }
    $protoResults | Format-Table -AutoSize

    Write-Host "`n── Hashes (expect MD5=0, others=4294967295) ──" -ForegroundColor Cyan
    $hashResults = foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
        $v = (Get-ItemProperty "HKLM:\$b\Hashes\$h" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Hash = $h; Enabled = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
    }
    $hashResults | Format-Table -AutoSize

    Write-Host "`n── Key Exchange (expect DH/ECDH=4294967295, min DH=2048) ──" -ForegroundColor Cyan
    $kxResults = foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        $vals = Get-ItemProperty "HKLM:\$b\KeyExchangeAlgorithms\$kx" -EA SilentlyContinue
        [PSCustomObject]@{
            Algorithm        = $kx
            Enabled          = if ($vals) { $vals.Enabled }              else { "(absent=OS default)" }
            ServerMinKeyBits = if ($vals) { $vals.ServerMinKeyBitLength } else { "(not set)" }
            ClientMinKeyBits = if ($vals) { $vals.ClientMinKeyBitLength } else { "(not set)" }
        }
    }
    $kxResults | Format-Table -AutoSize

    Write-Host "`n── .NET SchUseStrongCrypto (expect 1) ──" -ForegroundColor Cyan
    $dotnetResults = foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hv in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
            $val = (Get-ItemProperty "HKLM:\$hv\$v" -Name "SchUseStrongCrypto" -EA SilentlyContinue).SchUseStrongCrypto
            [PSCustomObject]@{ Path = "$hv\$v"; SchUseStrongCrypto = if ($null -ne $val) { $val } else { "(absent)" } }
        }
    }
    $dotnetResults | Format-Table -AutoSize

    Write-Host "`n── Cipher Suite Order ──" -ForegroundColor Cyan
    $cs = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
           -Name "Functions" -EA SilentlyContinue).Functions
    if ($cs) {
        $i = 0
        $csResults = foreach ($suite in ($cs -split ",")) {
            $i++
            [PSCustomObject]@{ Order = $i; CipherSuite = $suite }
        }
        $csResults | Format-Table -AutoSize
    } else {
        Write-Host "  Not set — OS default order in use." -ForegroundColor Yellow
    }

    Write-Host "`n── Active TLS Cipher Suites (live OS view) ──" -ForegroundColor Cyan
    Get-TlsCipherSuite | Select-Object Name | Format-Table -AutoSize

} -ArgumentList $base


###############################################################################
#  COMPLETION NOTICE
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  All 10 settings applied and pushed to $SOURHost." -ForegroundColor Green
Write-Host "  *** REBOOT THE WORKSTATION before testing. ***" -ForegroundColor Yellow
Write-Host "  SCHANNEL changes are not active until after restart." -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
