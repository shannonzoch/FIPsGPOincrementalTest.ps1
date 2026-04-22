###############################################################################
#  SOUR_Crypto_Incremental_Push.ps1
#
#  VERSION : 1.1.0
#
# ─────────────────────────────────────────────────────────────────────────────
#  CHANGE LOG
# ─────────────────────────────────────────────────────────────────────────────
#  v1.1.0  2026-04-22
#    - GPOName and SOURHost are now script parameters (-GPOName, -SOURHost)
#      instead of hardcoded variables. Both are mandatory; the script will
#      prompt if either is omitted at runtime.
#    - Added [CmdletBinding()] and param() block with Mandatory validation
#      and inline help text visible via Get-Help.
#    - Removed the "CONFIGURE THESE TWO VARIABLES" comment block — no longer
#      needed now that values are passed at invocation.
#    - Version and change log header added.
#
#  v1.0.0  (initial release)
#    - Interactive menu-driven incremental push of 10 strong-crypto policy
#      groups to a SOUR OU GPO from the Domain Controller.
#    - Fixed "empty pipe element" errors on all six foreach | Format-Table
#      locations by capturing loop output into intermediate variables first.
# ─────────────────────────────────────────────────────────────────────────────
#
#  PURPOSE : Incrementally push FIPS-equivalent strong crypto policies from
#            the Server 2022 DC to the SOUR workstation OU GPO.
#            Run each group, force-apply to the workstation, test, continue.
#
#  USAGE   :
#    .\SOUR_Crypto_Incremental_Push.ps1 -GPOName "SOUR-Workstation-Policy" `
#                                        -SOURHost "SOUR-WORKSTATION"
#
#    # Both parameters are mandatory. If omitted, PowerShell will prompt:
#    .\SOUR_Crypto_Incremental_Push.ps1
#
#  PRE-REQS: Run from an elevated PowerShell session on the Domain Controller.
#            ActiveDirectory and GroupPolicy modules must be available (RSAT).
#            The SOUR workstation must be reachable (ping, WinRM, admin share).
#
# ─────────────────────────────────────────────────────────────────────────────
#  HOW Set-GPRegistryValue WORKS (brief reference)
# ─────────────────────────────────────────────────────────────────────────────
#  Set-GPRegistryValue writes a registry value directly into a GPO's
#  registry.pol — no GPME needed. The workstation picks it up on the next
#  policy refresh. Syntax:
#
#    Set-GPRegistryValue `
#        -Name      "GPO Display Name"        # or -Guid for GUID
#        -Key       "HKLM\Full\Registry\Path" # HKLM or HKCU, backslashes
#        -ValueName "ValueName"
#        -Type      DWord | String | ...
#        -Value     <value>
#
#  To remove a value from the GPO (rollback):
#    Remove-GPRegistryValue -Name "..." -Key "..." -ValueName "..."
#
#  To force the workstation to pull immediately:
#    Invoke-GPUpdate -Computer "WORKSTATION_NAME" -Force -RandomDelayInMinutes 0
#
#  To verify what the GPO currently contains for a key:
#    Get-GPRegistryValue -Name "..." -Key "..." -ErrorAction SilentlyContinue
#
#  To verify what is LIVE on the workstation after the refresh:
#    Invoke-Command -ComputerName "WORKSTATION_NAME" -ScriptBlock {
#        Get-ItemProperty "HKLM:\..." -Name "..."
#    }
# ─────────────────────────────────────────────────────────────────────────────
#
#  GROUPS (apply in order — reboot workstation + test after each):
#    1 — Explicitly enable AES 128 and AES 256          (Very Low Risk)
#    2 — Enable SHA384 hash                              (Very Low Risk)
#    3 — Disable legacy protocols (SSL2/3, TLS 1.0/1.1) (Low Risk)
#    4 — Enable TLS 1.2 explicitly                       (Very Low Risk)
#    5 — Enable TLS 1.3                                  (Low Risk)
#    6 — Disable weak ciphers (RC4, RC2, DES, 3DES, NULL)(Medium Risk)
#    7 — Disable MD5, confirm SHA/256/512 enabled         (Low Risk)
#    8 — Key exchange + minimum DH 2048-bit              (Medium Risk)
#    9 — .NET Framework SchUseStrongCrypto               (Low Risk)
#   10 — Cipher suite order policy                       (Higher Risk)
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

# ── Helpers ──────────────────────────────────────────────────────────────────
function Set-CryptoValue {
    param([string]$Key, [string]$Name, $Value, [string]$Type = "DWord")
    Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
    Write-Host "   GPO SET  [$Name = $Value]  $Key" -ForegroundColor Gray
}

function Remove-CryptoValue {
    param([string]$Key, [string]$Name)
    try {
        Remove-GPRegistryValue -Name $GPOName -Key $Key -ValueName $Name -ErrorAction Stop | Out-Null
        Write-Host "   GPO REMOVED  [$Name]  $Key" -ForegroundColor Gray
    } catch {
        Write-Host "   GPO SKIP  (not present)  [$Name]  $Key" -ForegroundColor DarkGray
    }
}

function Push-AndVerify {
    param([string]$GroupLabel)
    Write-Host ""
    Write-Host "  Pushing policy to $SOURHost ..." -ForegroundColor Cyan
    try {
        Invoke-GPUpdate -Computer $SOURHost -Force -RandomDelayInMinutes 0 -ErrorAction Stop
        Write-Host "  gpupdate delivered to $SOURHost." -ForegroundColor Green
    } catch {
        Write-Warning "  Invoke-GPUpdate failed: $_"
        Write-Warning "  Fallback: run  gpupdate /force  manually on the workstation."
    }
    Write-Host ""
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Group $GroupLabel pushed." -ForegroundColor Green
    Write-Host "  Next steps on the WORKSTATION:" -ForegroundColor Yellow
    Write-Host "    1. Reboot (SCHANNEL changes require restart)"
    Write-Host "    2. Test the software thoroughly"
    Write-Host "    3. Return here and run the next group if tests pass"
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
}

function Check-LiveRegistry {
    # Queries the live registry on the workstation for all crypto keys
    # so you can confirm the GPO was applied before testing
    param([string]$RegPath, [string[]]$ValueNames)
    Write-Host "  Live check on $SOURHost ..." -ForegroundColor Cyan
    Invoke-Command -ComputerName $SOURHost -ScriptBlock {
        param($p, $names)
        foreach ($n in $names) {
            $v = (Get-ItemProperty $p -Name $n -ErrorAction SilentlyContinue).$n
            [PSCustomObject]@{ Path = $p; Name = $n; Value = if ($null -ne $v) { $v } else { "(absent)" } }
        }
    } -ArgumentList $RegPath,$ValueNames | Format-Table -AutoSize
}


###############################################################################
#  GROUP 1 — Explicitly Enable AES 128/256
#  Why first: Purely additive. Guarantees AES is available before anything
#  is disabled. Almost zero risk of breaking anything.
###############################################################################
function Apply-Group1 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 1 — Enable AES 128/256 Ciphers  [Very Low Risk]" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Set-CryptoValue "$base\Ciphers\AES 128/128" "Enabled" 1
    Set-CryptoValue "$base\Ciphers\AES 256/256" "Enabled" 1

    Push-AndVerify "1"
}

function Rollback-Group1 {
    Write-Host "  Rolling back Group 1..." -ForegroundColor Magenta
    Remove-CryptoValue "$base\Ciphers\AES 128/128" "Enabled"
    Remove-CryptoValue "$base\Ciphers\AES 256/256" "Enabled"
    Push-AndVerify "1 ROLLBACK"
}

function Verify-Group1 {
    foreach ($aes in @("AES 128/128","AES 256/256")) {
        try {
            Get-GPRegistryValue -Name $GPOName -Key "$base\Ciphers\$aes" -ErrorAction Stop |
                Select-Object KeyPath, ValueName, Value
        } catch { Write-Host "   NOT SET in GPO: $aes" -ForegroundColor Yellow }
    }
}


###############################################################################
#  GROUP 2 — Enable SHA384 Hash
#  Why: Completes SHA-2 family. Additive only, no disruption possible.
###############################################################################
function Apply-Group2 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 2 — Enable SHA384 Hash  [Very Low Risk]" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Set-CryptoValue "$base\Hashes\SHA384" "Enabled" 1

    Push-AndVerify "2"
}

function Rollback-Group2 {
    Write-Host "  Rolling back Group 2..." -ForegroundColor Magenta
    Remove-CryptoValue "$base\Hashes\SHA384" "Enabled"
    Push-AndVerify "2 ROLLBACK"
}


###############################################################################
#  GROUP 3 — Disable Legacy Protocols (SSL 2/3, TLS 1.0, TLS 1.1)
#  Sets both Enabled=0 AND DisabledByDefault=1 for belt-and-suspenders.
#  Risk: Low — these are already disabled by Windows defaults on modern OS.
#  Test: Any legacy integrations, VPN clients, older APIs the software calls.
###############################################################################
function Apply-Group3 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 3 — Disable Legacy Protocols  [Low Risk]" -ForegroundColor Cyan
    Write-Host "  Test: legacy API calls, VPN, any TLS made by the software" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
        foreach ($role in @("Server","Client")) {
            Set-CryptoValue "$base\Protocols\$proto\$role" "Enabled"          0
            Set-CryptoValue "$base\Protocols\$proto\$role" "DisabledByDefault" 1
        }
    }

    Push-AndVerify "3"
}

function Rollback-Group3 {
    Write-Host "  Rolling back Group 3..." -ForegroundColor Magenta
    foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
        foreach ($role in @("Server","Client")) {
            Remove-CryptoValue "$base\Protocols\$proto\$role" "Enabled"
            Remove-CryptoValue "$base\Protocols\$proto\$role" "DisabledByDefault"
        }
    }
    Push-AndVerify "3 ROLLBACK"
}


###############################################################################
#  GROUP 4 — Enable TLS 1.2 Explicitly
#  Risk: Very Low — TLS 1.2 is on by default on Win10; this just makes it
#  explicit and ensures DisabledByDefault=0 is set alongside Enabled=1.
###############################################################################
function Apply-Group4 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 4 — Explicitly Enable TLS 1.2  [Very Low Risk]" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($role in @("Server","Client")) {
        Set-CryptoValue "$base\Protocols\TLS 1.2\$role" "Enabled"          1
        Set-CryptoValue "$base\Protocols\TLS 1.2\$role" "DisabledByDefault" 0
    }

    Push-AndVerify "4"
}

function Rollback-Group4 {
    Write-Host "  Rolling back Group 4..." -ForegroundColor Magenta
    foreach ($role in @("Server","Client")) {
        Remove-CryptoValue "$base\Protocols\TLS 1.2\$role" "Enabled"
        Remove-CryptoValue "$base\Protocols\TLS 1.2\$role" "DisabledByDefault"
    }
    Push-AndVerify "4 ROLLBACK"
}


###############################################################################
#  GROUP 5 — Enable TLS 1.3
#  Risk: Low — silently ignored on Windows versions that don't support it.
#  Test: Any outbound TLS connections the software makes; some older TLS
#  stacks mishandle a TLS 1.3 ClientHello and drop the connection.
###############################################################################
function Apply-Group5 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 5 — Enable TLS 1.3  [Low Risk]" -ForegroundColor Cyan
    Write-Host "  Test: outbound connections; ignored on pre-Win10 1903" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($role in @("Server","Client")) {
        Set-CryptoValue "$base\Protocols\TLS 1.3\$role" "Enabled"          1
        Set-CryptoValue "$base\Protocols\TLS 1.3\$role" "DisabledByDefault" 0
    }

    Push-AndVerify "5"
}

function Rollback-Group5 {
    Write-Host "  Rolling back Group 5..." -ForegroundColor Magenta
    foreach ($role in @("Server","Client")) {
        Remove-CryptoValue "$base\Protocols\TLS 1.3\$role" "Enabled"
        Remove-CryptoValue "$base\Protocols\TLS 1.3\$role" "DisabledByDefault"
    }
    Push-AndVerify "5 ROLLBACK"
}


###############################################################################
#  GROUP 6 — Disable Weak Ciphers (RC4, RC2, DES, 3DES, NULL)
#  Risk: Medium — 3DES used by some legacy IIS/RDP; RC2 used by old COM
#  components. Test all inbound and outbound connections after applying.
###############################################################################
function Apply-Group6 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 6 — Disable Weak Ciphers  [Medium Risk]" -ForegroundColor Cyan
    Write-Host "  Test: RDP, any legacy COM/ODBC integrations, inbound TLS" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($c in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        Set-CryptoValue "$base\Ciphers\$c" "Enabled" 0
    }

    Push-AndVerify "6"
}

function Rollback-Group6 {
    Write-Host "  Rolling back Group 6..." -ForegroundColor Magenta
    foreach ($c in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        Remove-CryptoValue "$base\Ciphers\$c" "Enabled"
    }
    Push-AndVerify "6 ROLLBACK"
}


###############################################################################
#  GROUP 7 — Hash Algorithms (Disable MD5, Confirm SHA/256/512)
#  Risk: Low — MD5 should not be in active use; SHA family is additive.
#  Test: Any signature verification, certificate validation, HMAC operations.
###############################################################################
function Apply-Group7 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 7 — Hashes: Disable MD5, Enable SHA Family  [Low Risk]" -ForegroundColor Cyan
    Write-Host "  Test: certificate operations, signature verification" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Set-CryptoValue "$base\Hashes\MD5"    "Enabled" 0
    foreach ($h in @("SHA","SHA256","SHA512")) {
        Set-CryptoValue "$base\Hashes\$h" "Enabled" 1
    }

    Push-AndVerify "7"
}

function Rollback-Group7 {
    Write-Host "  Rolling back Group 7..." -ForegroundColor Magenta
    Remove-CryptoValue "$base\Hashes\MD5"    "Enabled"
    foreach ($h in @("SHA","SHA256","SHA512")) {
        Remove-CryptoValue "$base\Hashes\$h" "Enabled"
    }
    Push-AndVerify "7 ROLLBACK"
}


###############################################################################
#  GROUP 8 — Key Exchange Algorithms + Minimum DH Key Size (2048-bit)
#  Risk: Medium — the 2048-bit DH floor will reject any peer that only
#  supports 512 or 1024-bit DH. Test all outbound TLS connections.
###############################################################################
function Apply-Group8 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 8 — Key Exchange + Min DH 2048-bit  [Medium Risk]" -ForegroundColor Cyan
    Write-Host "  Test: ALL outbound TLS connections the software makes" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        Set-CryptoValue "$base\KeyExchangeAlgorithms\$kx" "Enabled" 1
    }
    Set-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength" 2048
    Set-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength" 2048

    Push-AndVerify "8"
}

function Rollback-Group8 {
    Write-Host "  Rolling back Group 8..." -ForegroundColor Magenta
    foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        Remove-CryptoValue "$base\KeyExchangeAlgorithms\$kx" "Enabled"
    }
    Remove-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength"
    Remove-CryptoValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength"
    Push-AndVerify "8 ROLLBACK"
}


###############################################################################
#  GROUP 9 — .NET Framework SchUseStrongCrypto
#  Risk: Low — forces .NET to use TLS 1.2+ instead of defaulting to older
#  protocols. Any .NET component in the software that hard-codes an older
#  ServicePointManager SecurityProtocol will fail. Test any .NET-based
#  features: web service calls, WCF endpoints, HttpClient usage.
###############################################################################
function Apply-Group9 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 9 — .NET SchUseStrongCrypto  [Low Risk]" -ForegroundColor Cyan
    Write-Host "  Test: any .NET web service calls or WCF in the software" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hive in @(
            "HKLM\SOFTWARE\Microsoft\.NETFramework",
            "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) {
            Set-CryptoValue "$hive\$v" "SchUseStrongCrypto" 1
        }
    }

    Push-AndVerify "9"
}

function Rollback-Group9 {
    Write-Host "  Rolling back Group 9..." -ForegroundColor Magenta
    foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hive in @(
            "HKLM\SOFTWARE\Microsoft\.NETFramework",
            "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) {
            Remove-CryptoValue "$hive\$v" "SchUseStrongCrypto"
        }
    }
    Push-AndVerify "9 ROLLBACK"
}


###############################################################################
#  GROUP 10 — Cipher Suite Order Policy
#  Risk: Higher — if the software or any dependency hard-codes a cipher not
#  in this list, TLS negotiation fails entirely. Apply last and test most
#  thoroughly. Check the software vendor's TLS requirements before applying.
###############################################################################
function Apply-Group10 {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Group 10 — Cipher Suite Order Policy  [Higher Risk]" -ForegroundColor Cyan
    Write-Host "  Test: ALL TLS paths — apply last, test most thoroughly" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    $ciphers = (
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
        -Value     $ciphers | Out-Null
    Write-Host "   GPO SET  [Functions = (9 cipher suites)]" -ForegroundColor Gray

    Push-AndVerify "10"
}

function Rollback-Group10 {
    Write-Host "  Rolling back Group 10..." -ForegroundColor Magenta
    Remove-GPRegistryValue `
        -Name      $GPOName `
        -Key       "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
        -ValueName "Functions" `
        -ErrorAction SilentlyContinue | Out-Null
    Push-AndVerify "10 ROLLBACK"
}


###############################################################################
#  VERIFY FUNCTION
#  Queries the live workstation registry to confirm all crypto settings are
#  active. Run after each reboot to confirm the GPO was applied correctly
#  before testing the software.
###############################################################################
function Verify-AllLive {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor White
    Write-Host "  Live Registry Verification on $SOURHost" -ForegroundColor White
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor White

    Invoke-Command -ComputerName $SOURHost -ScriptBlock {
        param($b)

        Write-Host "`n── AES Ciphers ──" -ForegroundColor Cyan
        $aesResults = foreach ($aes in @("AES 128/128","AES 256/256")) {
            $v = (Get-ItemProperty "$b\Ciphers\$aes" -EA SilentlyContinue).Enabled
            [PSCustomObject]@{ Setting = "Cipher: $aes"; Value = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
        }
        $aesResults | Format-Table -AutoSize

        Write-Host "`n── Weak Ciphers (should all be 0) ──" -ForegroundColor Cyan
        $weakResults = foreach ($c in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
                          "RC2 128/128","RC2 56/128","RC2 40/128",
                          "DES 56/56","Triple DES 168","NULL")) {
            $v = (Get-ItemProperty "$b\Ciphers\$c" -EA SilentlyContinue).Enabled
            [PSCustomObject]@{ Cipher = $c; Enabled = if ($null -ne $v) { $v } else { "(absent)" } }
        }
        $weakResults | Format-Table -AutoSize

        Write-Host "`n── Protocols ──" -ForegroundColor Cyan
        $protoResults = foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
            foreach ($r in @("Server","Client")) {
                $vals = Get-ItemProperty "$b\Protocols\$p\$r" -EA SilentlyContinue
                [PSCustomObject]@{
                    Protocol          = $p
                    Role              = $r
                    Enabled           = if ($vals) { $vals.Enabled }           else { "(absent=OS default)" }
                    DisabledByDefault = if ($vals) { $vals.DisabledByDefault } else { "(absent=OS default)" }
                }
            }
        }
        $protoResults | Format-Table -AutoSize

        Write-Host "`n── Hashes ──" -ForegroundColor Cyan
        $hashResults = foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
            $v = (Get-ItemProperty "$b\Hashes\$h" -EA SilentlyContinue).Enabled
            [PSCustomObject]@{ Hash = $h; Enabled = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
        }
        $hashResults | Format-Table -AutoSize

        Write-Host "`n── Key Exchange ──" -ForegroundColor Cyan
        $kxResults = foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
            $vals = Get-ItemProperty "$b\KeyExchangeAlgorithms\$kx" -EA SilentlyContinue
            [PSCustomObject]@{
                Algorithm         = $kx
                Enabled           = if ($vals) { $vals.Enabled }               else { "(absent=OS default)" }
                ServerMinKeyBits  = if ($vals) { $vals.ServerMinKeyBitLength }  else { "(not set)" }
                ClientMinKeyBits  = if ($vals) { $vals.ClientMinKeyBitLength }  else { "(not set)" }
            }
        }
        $kxResults | Format-Table -AutoSize

        Write-Host "`n── .NET SchUseStrongCrypto ──" -ForegroundColor Cyan
        $dotnetResults = foreach ($v in @("v4.0.30319","v2.0.50727")) {
            foreach ($hv in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
                $val = (Get-ItemProperty "HKLM:\$hv\$v" -Name "SchUseStrongCrypto" -EA SilentlyContinue).SchUseStrongCrypto
                [PSCustomObject]@{ Path = "$hv\$v"; SchUseStrongCrypto = if ($null -ne $val) { $val } else { "(absent)" } }
            }
        }
        $dotnetResults | Format-Table -AutoSize

        Write-Host "`n── Cipher Suite Order ──" -ForegroundColor Cyan
        $cs = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -EA SilentlyContinue).Functions
        if ($cs) { $cs -split "," | ForEach-Object { [PSCustomObject]@{ CipherSuite = $_ } } | Format-Table -AutoSize }
        else      { Write-Host "  Not set — OS default order in use." }

        Write-Host "`n── Active TLS Cipher Suites (live OS view) ──" -ForegroundColor Cyan
        Get-TlsCipherSuite | Select-Object Name | Format-Table -AutoSize

    } -ArgumentList $base
}


###############################################################################
#  INTERACTIVE MENU
###############################################################################
function Show-Menu {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  SOUR OU Crypto Push  |  GPO: $GPOName  |  Target: $SOURHost" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  APPLY                              ROLLBACK"
    Write-Host "  [1]  Enable AES 128/256            [R1]  Rollback Group 1"
    Write-Host "  [2]  Enable SHA384                 [R2]  Rollback Group 2"
    Write-Host "  [3]  Disable legacy protocols      [R3]  Rollback Group 3"
    Write-Host "  [4]  Enable TLS 1.2 explicitly     [R4]  Rollback Group 4"
    Write-Host "  [5]  Enable TLS 1.3                [R5]  Rollback Group 5"
    Write-Host "  [6]  Disable weak ciphers          [R6]  Rollback Group 6"
    Write-Host "  [7]  Hashes (MD5 off, SHA on)      [R7]  Rollback Group 7"
    Write-Host "  [8]  Key exchange + DH 2048-bit    [R8]  Rollback Group 8"
    Write-Host "  [9]  .NET SchUseStrongCrypto        [R9]  Rollback Group 9"
    Write-Host "  [10] Cipher suite order            [R10] Rollback Group 10"
    Write-Host ""
    Write-Host "  [V]  Verify live registry on workstation"
    Write-Host "  [Q]  Quit"
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    return (Read-Host "  Choice").Trim()
}

# ── Main loop ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Verifying GPO exists..." -ForegroundColor Gray
try {
    Get-GPO -Name $GPOName -ErrorAction Stop | Out-Null
    Write-Host "  GPO found: $GPOName" -ForegroundColor Green
} catch {
    Write-Error "GPO '$GPOName' not found. Check the `$GPOName variable at the top of this script."
    exit 1
}

do {
    $choice = Show-Menu
    switch ($choice) {
        "1"   { Apply-Group1  }
        "2"   { Apply-Group2  }
        "3"   { Apply-Group3  }
        "4"   { Apply-Group4  }
        "5"   { Apply-Group5  }
        "6"   { Apply-Group6  }
        "7"   { Apply-Group7  }
        "8"   { Apply-Group8  }
        "9"   { Apply-Group9  }
        "10"  { Apply-Group10 }
        "R1"  { Rollback-Group1  }
        "R2"  { Rollback-Group2  }
        "R3"  { Rollback-Group3  }
        "R4"  { Rollback-Group4  }
        "R5"  { Rollback-Group5  }
        "R6"  { Rollback-Group6  }
        "R7"  { Rollback-Group7  }
        "R8"  { Rollback-Group8  }
        "R9"  { Rollback-Group9  }
        "R10" { Rollback-Group10 }
        "V"   { Verify-AllLive   }
        "Q"   { Write-Host "  Exiting." -ForegroundColor DarkGray }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
} while ($choice -ne "Q")
