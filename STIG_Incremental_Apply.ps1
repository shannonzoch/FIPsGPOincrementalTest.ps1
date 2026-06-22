#Requires -RunAsAdministrator
###############################################################################
#  STIG_Incremental_Apply.ps1
#
#  PURPOSE:  Re-applies DISA STIG settings for Windows 10/11 in small,
#            logically grouped batches so software can be tested after each
#            group to identify which setting causes failures.
#
#  LGPO.exe: Download from Microsoft Security Compliance Toolkit (SCT):
#            https://www.microsoft.com/en-us/download/details.aspx?id=55319
#            Place LGPO.exe in the same folder as this script.
#
#  USAGE:    Run the script. An interactive menu appears. Apply one group
#            at a time, reboot, test the software, then return to apply the
#            next group. Each group has a built-in rollback option.
#
#  GROUPS:
#    A  - Audit Policies                         (Very Low Risk)
#    B  - Account / Password / Lockout Policy    (Low Risk)
#    C  - LSA & Network Authentication Settings  (Medium Risk)
#    D  - UAC Settings                           (Medium Risk)
#    E  - TLS / SCHANNEL / Cipher Hardening      (High Risk)
#    F  - User Rights Assignments                (Medium-High Risk)
#    G  - Security Options & Misc Registry       (Medium Risk)
#    H  - Administrative Templates               (Variable Risk)
###############################################################################

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Locate LGPO.exe ──────────────────────────────────────────────────────────
$lgpo = $null
foreach ($candidate in @(
    (Join-Path $ScriptDir "LGPO.exe"),
    "C:\Tools\LGPO.exe",
    "C:\Windows\System32\LGPO.exe",
    (Get-Command "LGPO.exe" -ErrorAction SilentlyContinue)?.Source
)) {
    if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
        $lgpo = $candidate; break
    }
}

Write-Host ""
if ($lgpo) {
    Write-Host "  [OK] LGPO.exe: $lgpo" -ForegroundColor Green
} else {
    Write-Host "  [!!] LGPO.exe not found. Groups using LGPO will fall back to direct secedit/registry." -ForegroundColor Yellow
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Banner {
    param([string]$Title,[string]$Risk,[string]$Color="Cyan")
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "  Risk Level: $Risk" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $Color
}

function Apply-LgpoText {
    param([string]$Content)
    $tmp = "$env:TEMP\lgpo_apply_$([System.IO.Path]::GetRandomFileName()).txt"
    Set-Content -Path $tmp -Value $Content -Encoding ASCII
    if ($lgpo) {
        & $lgpo /t $tmp /q
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

function Apply-SeceditInf {
    param([string]$InfContent)
    $inf = "$env:TEMP\stig_apply_$([System.IO.Path]::GetRandomFileName()).inf"
    $db  = "$env:TEMP\stig_apply_$([System.IO.Path]::GetRandomFileName()).sdb"
    Set-Content -Path $inf -Value $InfContent -Encoding Unicode
    secedit /configure /db $db /cfg $inf /quiet
    Remove-Item $inf,$db -Force -ErrorAction SilentlyContinue
}

function Apply-AuditPol {
    param([hashtable]$Settings)
    foreach ($entry in $Settings.GetEnumerator()) {
        $sc = if ($entry.Value -band 1) { "enable" } else { "disable" }
        $fc = if ($entry.Value -band 2) { "enable" } else { "disable" }
        auditpol /set /subcategory:"$($entry.Key)" /success:$sc /failure:$fc 2>&1 | Out-Null
    }
}

function Set-RegDWord {
    param([string]$Path,[string]$Name,[int]$Value)
    New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Host "   SET  $Name = $Value" -ForegroundColor Gray
}

function Remove-RegValueIfExists {
    param([string]$Path,[string]$Name)
    if ((Test-Path $Path) -and (Get-ItemProperty $Path -Name $Name -ErrorAction SilentlyContinue)) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        Write-Host "   REMOVED  $Name  |  $Path" -ForegroundColor Gray
    }
}

function Prompt-Continue {
    param([string]$GroupName)
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Group $GroupName applied." -ForegroundColor Green
    Write-Host "  ACTION REQUIRED:" -ForegroundColor Yellow
    Write-Host "    1. Run: gpupdate /force" -ForegroundColor White
    Write-Host "    2. REBOOT the workstation" -ForegroundColor White
    Write-Host "    3. Test your software thoroughly" -ForegroundColor White
    Write-Host "    4. Return to this script and apply the next group" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

###############################################################################
#  INTERACTIVE MENU
###############################################################################
function Show-Menu {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  STIG INCREMENTAL APPLY — Select a group to apply" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  [A]  Audit Policies                        (Very Low Risk)" -ForegroundColor Cyan
    Write-Host "  [B]  Account / Password / Lockout Policy   (Low Risk)" -ForegroundColor Cyan
    Write-Host "  [C]  LSA & Network Authentication          (Medium Risk)" -ForegroundColor Yellow
    Write-Host "  [D]  UAC Settings                          (Medium Risk)" -ForegroundColor Yellow
    Write-Host "  [E]  TLS / SCHANNEL / Cipher Hardening     (High Risk)" -ForegroundColor Red
    Write-Host "  [F]  User Rights Assignments               (Medium-High Risk)" -ForegroundColor Yellow
    Write-Host "  [G]  Security Options & Misc Registry      (Medium Risk)" -ForegroundColor Yellow
    Write-Host "  [H]  Administrative Templates              (Variable Risk)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [R]  Rollback a group" -ForegroundColor Magenta
    Write-Host "  [Q]  Quit" -ForegroundColor DarkGray
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host ""
    return (Read-Host "  Enter choice").ToUpper().Trim()
}

function Show-RollbackMenu {
    Write-Host ""
    Write-Host "  ROLLBACK — Which group to roll back?"
    Write-Host "  [A] Audit Policies   [B] Account Policy   [C] LSA/Network"
    Write-Host "  [D] UAC              [E] TLS/SCHANNEL      [F] User Rights"
    Write-Host "  [G] Security Options [H] Admin Templates"
    Write-Host ""
    return (Read-Host "  Enter group letter").ToUpper().Trim()
}

###############################################################################
#  GROUP A — AUDIT POLICIES
#  Risk: Very Low — purely sets what gets logged; cannot break functionality
###############################################################################
function Apply-GroupA {
    Write-Banner "Group A — Advanced Audit Policies (WN10-AU)" "Very Low — logging only, cannot break software"

    Write-Host "  Applying advanced audit policy via auditpol..." -ForegroundColor Gray

    # Audit values: 1=Success, 2=Failure, 3=Success+Failure, 0=No Auditing
    $auditSettings = @{
        # Account Logon
        "Credential Validation"                 = 3   # WN10-AU-000500/510
        "Kerberos Authentication Service"       = 2
        "Kerberos Service Ticket Operations"    = 2
        # Account Management
        "Computer Account Management"           = 1   # WN10-AU-000054
        "Other Account Management Events"       = 1
        "Security Group Management"             = 1   # WN10-AU-000057
        "User Account Management"              = 3   # WN10-AU-000060/063
        # Detailed Tracking
        "Plug and Play Events"                  = 1   # WN10-AU-000030
        "Process Creation"                      = 1   # WN10-AU-000033
        # Logon/Logoff
        "Account Lockout"                       = 2   # WN10-AU-000036
        "Group Membership"                      = 1   # WN10-AU-000039
        "Logoff"                                = 1   # WN10-AU-000042
        "Logon"                                 = 3   # WN10-AU-000044/046
        "Network Policy Server"                 = 3
        "Other Logon/Logoff Events"             = 3   # WN10-AU-000049
        "Special Logon"                         = 1   # WN10-AU-000052
        # Object Access
        "Removable Storage"                     = 3   # WN10-AU-000555
        "Other Object Access Events"            = 2
        # Policy Change
        "Audit Policy Change"                   = 1   # WN10-AU-000072
        "Authentication Policy Change"          = 1   # WN10-AU-000075
        "Authorization Policy Change"           = 1
        "MPSSVC Rule-Level Policy Change"       = 3   # WN10-AU-000081
        "Other Policy Change Events"            = 2
        # Privilege Use
        "Sensitive Privilege Use"               = 3   # WN10-AU-000084/087
        # System
        "IPSec Driver"                          = 3   # WN10-AU-000090
        "Other System Events"                   = 3
        "Security State Change"                 = 1   # WN10-AU-000096
        "Security System Extension"             = 1   # WN10-AU-000099
        "System Integrity"                      = 3   # WN10-AU-000102/105
    }

    Apply-AuditPol -Settings $auditSettings

    Write-Host "   DONE: Advanced audit policy applied." -ForegroundColor Green
    Prompt-Continue "A"
}

function Rollback-GroupA {
    Write-Host "  Rolling back Group A — clearing all audit policies..." -ForegroundColor Magenta
    auditpol /clear /y | Out-Null
    # Restore Windows defaults
    auditpol /set /subcategory:"Credential Validation"   /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logon"                   /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logoff"                  /success:enable                | Out-Null
    auditpol /set /subcategory:"Account Lockout"         /failure:enable                | Out-Null
    auditpol /set /subcategory:"Special Logon"           /success:enable                | Out-Null
    Write-Host "  DONE: Audit policies cleared to Windows defaults." -ForegroundColor Green
}


###############################################################################
#  GROUP B — ACCOUNT / PASSWORD / LOCKOUT POLICY
#  Risk: Low — affects login behaviour, not application crypto
###############################################################################
function Apply-GroupB {
    Write-Banner "Group B — Account, Password & Lockout Policy (WN10-AC)" "Low — login behaviour only"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 3
ResetLockoutCount = 15
LockoutDuration = 15
EnableGuestAccount = 0
"@
    Apply-SeceditInf $inf
    Write-Host "   SET: MinPasswordAge=1, MaxAge=60, MinLen=14, Complexity=On, History=24"   -ForegroundColor Gray
    Write-Host "   SET: Lockout threshold=3, Reset=15min, Duration=15min, Guest=Disabled"    -ForegroundColor Gray
    Write-Host "   DONE." -ForegroundColor Green
    Prompt-Continue "B"
}

function Rollback-GroupB {
    Write-Host "  Rolling back Group B — resetting account policy to defaults..." -ForegroundColor Magenta
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 42
MinimumPasswordLength = 0
PasswordComplexity = 0
PasswordHistorySize = 0
LockoutBadCount = 0
ResetLockoutCount = 30
LockoutDuration = 30
"@
    Apply-SeceditInf $inf
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  GROUP C — LSA & NETWORK AUTHENTICATION
#  Risk: Medium — NTLMv2 requirement can break legacy auth; test network access
###############################################################################
function Apply-GroupC {
    Write-Banner "Group C — LSA & Network Authentication (WN10-SO)" "Medium — test all network connections and shares after applying"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,2
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
"@
    Apply-SeceditInf $inf

    Write-Host "   SET: LmCompatibilityLevel=5 (NTLMv2 only, refuse LM+NTLM)" -ForegroundColor Gray
    Write-Host "   SET: NoLMHash=1, SMB signing required, LDAP signing required" -ForegroundColor Gray
    Write-Host "   SET: NTLMMinSec=537395200 (NTLMv2+128-bit encryption required)" -ForegroundColor Gray
    Write-Host "   SET: RestrictAnonymous=1, DisableDomainCreds=1" -ForegroundColor Gray
    Write-Host "   DONE." -ForegroundColor Green
    Prompt-Continue "C"
}

function Rollback-GroupC {
    Write-Host "  Rolling back Group C — resetting LSA/network auth to defaults..." -ForegroundColor Magenta
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,3
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
"@
    Apply-SeceditInf $inf
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  GROUP D — UAC SETTINGS
#  Risk: Medium — UAC prompts may change; test software that auto-elevates
###############################################################################
function Apply-GroupD {
    Write-Banner "Group D — UAC Settings (WN10-SO)" "Medium — test software that installs, auto-elevates, or uses COM"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
"@
    Apply-SeceditInf $inf

    Write-Host "   SET: UAC=Enabled, AdminPrompt=Credentials on secure desktop" -ForegroundColor Gray
    Write-Host "   SET: UserElevation=Denied, InstallerDetection=On, FilterAdmin=On" -ForegroundColor Gray
    Write-Host "   DONE." -ForegroundColor Green
    Prompt-Continue "D"
}

function Rollback-GroupD {
    Write-Host "  Rolling back Group D — resetting UAC to defaults..." -ForegroundColor Magenta
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0
"@
    Apply-SeceditInf $inf
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  GROUP E — TLS / SCHANNEL / CIPHER HARDENING
#  Risk: High — most likely to break software using TLS/crypto
#  Applied as five sub-groups (E1–E5) for maximum granularity
###############################################################################
function Apply-GroupE {
    Write-Banner "Group E — TLS / SCHANNEL / Cipher Hardening" "HIGH — apply sub-groups E1 through E5 one at a time and reboot between each"

    Write-Host ""
    Write-Host "  This group is split into 5 sub-groups for maximum test granularity." -ForegroundColor Yellow
    Write-Host "  Apply each sub-group, reboot, test, then continue." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [E1]  Disable legacy protocols (SSL 2/3, TLS 1.0/1.1) + DisabledByDefault keys"
    Write-Host "  [E2]  Enable TLS 1.2 (Enabled + DisabledByDefault)"
    Write-Host "  [E3]  Enable TLS 1.3"
    Write-Host "  [E4]  Disable weak ciphers (RC4, RC2, DES, 3DES, NULL) + Enable AES"
    Write-Host "  [E5]  Hashes + Key Exchange + Min DH size + Cipher suite order + .NET"
    Write-Host "  [EB]  Back to main menu"
    Write-Host ""

    $sub = (Read-Host "  Enter sub-group (E1-E5 or EB)").ToUpper().Trim()

    switch ($sub) {
        "E1" {
            Write-Host "  Applying E1 — Disabling legacy protocols..." -ForegroundColor Cyan
            foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
                foreach ($r in @("Server","Client")) {
                    Set-RegDWord "$schannel\Protocols\$p\$r" "Enabled" 0
                    Set-RegDWord "$schannel\Protocols\$p\$r" "DisabledByDefault" 1
                }
            }
            Write-Host "   DONE: SSL 2/3, TLS 1.0/1.1 disabled with DisabledByDefault=1." -ForegroundColor Green
            Prompt-Continue "E1"
        }
        "E2" {
            Write-Host "  Applying E2 — Enabling TLS 1.2..." -ForegroundColor Cyan
            foreach ($r in @("Server","Client")) {
                Set-RegDWord "$schannel\Protocols\TLS 1.2\$r" "Enabled" 1
                Set-RegDWord "$schannel\Protocols\TLS 1.2\$r" "DisabledByDefault" 0
            }
            Write-Host "   DONE: TLS 1.2 explicitly enabled." -ForegroundColor Green
            Prompt-Continue "E2"
        }
        "E3" {
            Write-Host "  Applying E3 — Enabling TLS 1.3..." -ForegroundColor Cyan
            foreach ($r in @("Server","Client")) {
                Set-RegDWord "$schannel\Protocols\TLS 1.3\$r" "Enabled" 1
                Set-RegDWord "$schannel\Protocols\TLS 1.3\$r" "DisabledByDefault" 0
            }
            Write-Host "   DONE: TLS 1.3 enabled (ignored on pre-Win10 1903)." -ForegroundColor Green
            Prompt-Continue "E3"
        }
        "E4" {
            Write-Host "  Applying E4 — Weak ciphers disabled, AES enabled..." -ForegroundColor Cyan
            foreach ($c in @("RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
                             "RC2 128/128","RC2 56/128","RC2 40/128",
                             "DES 56/56","Triple DES 168","NULL")) {
                Set-RegDWord "$schannel\Ciphers\$c" "Enabled" 0
            }
            foreach ($aes in @("AES 128/128","AES 256/256")) {
                Set-RegDWord "$schannel\Ciphers\$aes" "Enabled" 1
            }
            Write-Host "   DONE: Weak ciphers off; AES 128/256 explicitly on." -ForegroundColor Green
            Prompt-Continue "E4"
        }
        "E5" {
            Write-Host "  Applying E5 — Hashes, key exchange, DH size, cipher order, .NET..." -ForegroundColor Cyan
            # Hashes
            Set-RegDWord "$schannel\Hashes\MD5"    "Enabled" 0
            foreach ($h in @("SHA","SHA256","SHA384","SHA512")) {
                Set-RegDWord "$schannel\Hashes\$h" "Enabled" 1
            }
            # Key Exchange
            foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
                Set-RegDWord "$schannel\KeyExchangeAlgorithms\$kx" "Enabled" 1
            }
            # Min DH key size
            Set-RegDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength" 2048
            Set-RegDWord "$schannel\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength" 2048
            # Cipher suite order
            $ciphers = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256," +
                       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," +
                       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256," +
                       "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
            $csPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
            New-Item -Path $csPath -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $csPath -Name "Functions" -Value $ciphers -Type String
            # .NET strong crypto
            foreach ($v in @("v4.0.30319","v2.0.50727")) {
                foreach ($hv in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
                    Set-RegDWord "HKLM:\$hv\$v" "SchUseStrongCrypto" 1
                }
            }
            Write-Host "   DONE: Hashes, KX, DH min size, cipher order, .NET all set." -ForegroundColor Green
            Prompt-Continue "E5"
        }
        "EB" { return }
        default { Write-Host "  Invalid sub-group." -ForegroundColor Red }
    }
}

function Rollback-GroupE {
    Write-Host "  Rolling back Group E — removing all SCHANNEL/TLS/cipher keys..." -ForegroundColor Magenta
    foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
        foreach ($r in @("Server","Client")) {
            $path = "$schannel\Protocols\$p\$r"
            if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    foreach ($c in @("AES 128/128","AES 256/256","RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
                     "RC2 128/128","RC2 56/128","RC2 40/128","DES 56/56","Triple DES 168","NULL")) {
        if (Test-Path "$schannel\Ciphers\$c") { Remove-Item "$schannel\Ciphers\$c" -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
        if (Test-Path "$schannel\Hashes\$h") { Remove-Item "$schannel\Hashes\$h" -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        Remove-RegValueIfExists "$schannel\KeyExchangeAlgorithms\$kx" "Enabled"
        Remove-RegValueIfExists "$schannel\KeyExchangeAlgorithms\$kx" "ServerMinKeyBitLength"
        Remove-RegValueIfExists "$schannel\KeyExchangeAlgorithms\$kx" "ClientMinKeyBitLength"
    }
    Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "Functions"
    foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hv in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
            Remove-RegValueIfExists "HKLM:\$hv\$v" "SchUseStrongCrypto"
        }
    }
    Write-Host "  DONE: All SCHANNEL keys removed — OS defaults restored." -ForegroundColor Green
}


###############################################################################
#  GROUP F — USER RIGHTS ASSIGNMENTS
#  Risk: Medium-High — restricts who/what can perform privileged operations
###############################################################################
function Apply-GroupF {
    Write-Banner "Group F — User Rights Assignments (WN10-UR)" "Medium-High — test all user logon types and privileged application functions"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyNetworkLogonRight = *S-1-5-7,Guest
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyInteractiveLogonRight = *S-1-5-7
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyRemoteInteractiveLogonRight = *S-1-5-7,Guest,*S-1-5-32-546
SeServiceLogonRight =
SeDenyServiceLogonRight = *S-1-5-7,Guest
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeDenyBatchLogonRight = *S-1-5-7,Guest
SeBackupPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeDebugPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeTcbPrivilege =
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeCreatePermanentPrivilege =
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege =
SeSecurityPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeEnableDelegationPrivilege =
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545,*S-1-5-90-0
SeManageVolumePrivilege = *S-1-5-32-544
SeRelabelPrivilege =
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeSyncAgentPrivilege =
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545
SeTrustedCredManAccessPrivilege =
"@
    Apply-SeceditInf $inf

    Write-Host "   SET: Network logon — Admins/Users/Backup Operators only" -ForegroundColor Gray
    Write-Host "   SET: Deny logon — Anonymous Logon (S-1-5-7) and Guest denied all types" -ForegroundColor Gray
    Write-Host "   SET: Debug privilege — Admins only; Create token — nobody" -ForegroundColor Gray
    Write-Host "   DONE." -ForegroundColor Green
    Prompt-Continue "F"
}

function Rollback-GroupF {
    Write-Host "  Rolling back Group F — restoring default user rights..." -ForegroundColor Magenta
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyNetworkLogonRight =
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyInteractiveLogonRight =
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyRemoteInteractiveLogonRight =
SeDenyBatchLogonRight =
SeDenyServiceLogonRight =
SeDebugPrivilege = *S-1-5-32-544
"@
    Apply-SeceditInf $inf
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  GROUP G — SECURITY OPTIONS & MISC REGISTRY
#  Risk: Medium — WDigest, LSASS protection, screen saver, RDP settings
###############################################################################
function Apply-GroupG {
    Write-Banner "Group G — Security Options & Misc Registry (WN10-SO)" "Medium — test RDP, screen lock, and any app using WDigest or LSASS directly"

    # WDigest — prevents creds being stored in plaintext in memory
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0
    Write-Host "   SET: WDigest UseLogonCredential=0 (WN10-SO-000195)" -ForegroundColor Gray

    # LSASS protection (Run as PPL)
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1
    Write-Host "   SET: LSASS RunAsPPL=1 (WN10-SO-000140)" -ForegroundColor Gray

    # LSASS audit mode (logs before enforcing PPL — safe first step)
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "AuditBaseObjects" 0
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" 0
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" 1

    # Safe DLL search mode
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode" 1
    Write-Host "   SET: SafeDllSearchMode=1" -ForegroundColor Gray

    # Clear Page File at Shutdown (WN10-SO-000245)
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0

    # Printer driver installation restricted to admins (WN10-SO-000100)
    Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" 1
    Write-Host "   SET: Printer driver install restricted to admins" -ForegroundColor Gray

    # Screen saver timeout and lock (WN10-SO)
    $lgpoText = @"
; Screen saver / interactive lock settings
Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaveTimeOut
SZ:900

Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaverIsSecure
SZ:1

Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaveActive
SZ:1

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\System
InactivityTimeoutSecs
DWORD:900

"@
    Apply-LgpoText $lgpoText
    Write-Host "   SET: Screen saver timeout=900s, locked, interactive timeout=900s" -ForegroundColor Gray

    # Disable solicited and unsolicited Remote Assistance
    Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" 0
    Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" 0
    Write-Host "   SET: Remote Assistance disabled (WN10-CC-000155/165)" -ForegroundColor Gray

    Write-Host "   DONE." -ForegroundColor Green
    Prompt-Continue "G"
}

function Rollback-GroupG {
    Write-Host "  Rolling back Group G..." -ForegroundColor Magenta
    Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
    Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
    Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown"
    Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
    Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"
    Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"
    # Clear screen saver GPO entries
    $lgpoText = @"
Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaveTimeOut
DELETE

Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaverIsSecure
DELETE

Computer
Software\Policies\Microsoft\Windows\Control Panel\Desktop
ScreenSaveActive
DELETE

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\System
InactivityTimeoutSecs
DELETE

"@
    Apply-LgpoText $lgpoText
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  GROUP H — ADMINISTRATIVE TEMPLATES
#  Risk: Variable — AutoPlay/WER unlikely to break; RDP/PowerShell logging
#        and SmartScreen settings more likely to affect application behaviour
###############################################################################
function Apply-GroupH {
    Write-Banner "Group H — Administrative Templates (WN10-CC)" "Variable — split into H1/H2; test each separately"

    Write-Host ""
    Write-Host "  [H1]  AutoPlay/AutoRun, Error Reporting, Attachment Manager   (Low Risk)"
    Write-Host "  [H2]  RDP security, PowerShell logging, SmartScreen, CredSSP  (Medium Risk)"
    Write-Host "  [HB]  Back to main menu"
    Write-Host ""

    $sub = (Read-Host "  Enter sub-group (H1, H2, or HB)").ToUpper().Trim()

    switch ($sub) {
        "H1" {
            Write-Host "  Applying H1 — AutoPlay, Error Reporting, Attachment Manager..." -ForegroundColor Cyan
            $lgpoText = @"
; AutoPlay/AutoRun (WN10-CC-000185/190/195)
Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoDriveTypeAutoRun
DWORD:255

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoAutorun
DWORD:1

Computer
Software\Policies\Microsoft\Windows\Explorer
NoAutoplayfornonVolume
DWORD:1

; Windows Error Reporting (WN10-CC-000039)
Computer
Software\Policies\Microsoft\Windows\Windows Error Reporting
Disabled
DWORD:1

; Attachment Manager — save zone info (WN10-CC-000010)
Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Attachments
SaveZoneInformation
DWORD:1

; Installer always-elevate disabled (WN10-CC-000315)
Computer
Software\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated
DWORD:0

User
Software\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated
DWORD:0

; Allow indexing of encrypted files — disabled (WN10-CC-000080)
Computer
Software\Policies\Microsoft\Windows\Windows Search
AllowIndexingEncryptedStoresOrItems
DWORD:0

; Early launch anti-malware driver (WN10-CC-000055)
Computer
System\CurrentControlSet\Policies\EarlyLaunch
DriverLoadPolicy
DWORD:3

"@
            Apply-LgpoText $lgpoText
            Write-Host "   DONE: H1 applied." -ForegroundColor Green
            Prompt-Continue "H1"
        }
        "H2" {
            Write-Host "  Applying H2 — RDP security, PowerShell logging, SmartScreen, CredSSP..." -ForegroundColor Cyan
            $lgpoText = @"
; RDP — require NLA (WN10-CC-000290)
Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
UserAuthentication
DWORD:1

; RDP — set security layer to SSL/TLS (WN10-CC-000295)
Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
SecurityLayer
DWORD:2

; RDP — high encryption level (WN10-CC-000300)
Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
MinEncryptionLevel
DWORD:3

; RDP — disable drive redirection (WN10-CC-000030)
Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
fDisableCdm
DWORD:1

; RDP — always prompt for password (WN10-CC-000280)
Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
fPromptForPassword
DWORD:1

; PowerShell — Script Block Logging (WN10-CC-000326)
Computer
Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging
DWORD:1

; SmartScreen — Explorer (WN10-CC-000400)
Computer
Software\Policies\Microsoft\Windows\System
EnableSmartScreen
DWORD:1

Computer
Software\Policies\Microsoft\Windows\System
ShellSmartScreenLevel
SZ:Block

; CredSSP — require NTLMv2 and 128-bit encryption (WN10-CC-000230)
Computer
Software\Policies\Microsoft\Windows\CredentialsDelegation
AllowProtectedCreds
DWORD:1

; Data Collection — limit telemetry to Security level (WN10-CC-000327)
Computer
Software\Policies\Microsoft\Windows\DataCollection
AllowTelemetry
DWORD:0

"@
            Apply-LgpoText $lgpoText
            Write-Host "   DONE: H2 applied." -ForegroundColor Green
            Prompt-Continue "H2"
        }
        "HB" { return }
        default { Write-Host "  Invalid sub-group." -ForegroundColor Red }
    }
}

function Rollback-GroupH {
    Write-Host "  Rolling back Group H — removing Administrative Template settings..." -ForegroundColor Magenta
    $lgpoText = @"
Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoDriveTypeAutoRun
DELETE

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoAutorun
DELETE

Computer
Software\Policies\Microsoft\Windows\Explorer
NoAutoplayfornonVolume
DELETE

Computer
Software\Policies\Microsoft\Windows\Windows Error Reporting
Disabled
DELETE

Computer
Software\Microsoft\Windows\CurrentVersion\Policies\Attachments
SaveZoneInformation
DELETE

Computer
Software\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated
DELETE

User
Software\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated
DELETE

Computer
Software\Policies\Microsoft\Windows\Windows Search
AllowIndexingEncryptedStoresOrItems
DELETE

Computer
System\CurrentControlSet\Policies\EarlyLaunch
DriverLoadPolicy
DELETE

Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
UserAuthentication
DELETE

Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
SecurityLayer
DELETE

Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
MinEncryptionLevel
DELETE

Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
fDisableCdm
DELETE

Computer
Software\Policies\Microsoft\Windows NT\Terminal Services
fPromptForPassword
DELETE

Computer
Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging
DELETE

Computer
Software\Policies\Microsoft\Windows\System
EnableSmartScreen
DELETE

Computer
Software\Policies\Microsoft\Windows\System
ShellSmartScreenLevel
DELETE

Computer
Software\Policies\Microsoft\Windows\CredentialsDelegation
AllowProtectedCreds
DELETE

Computer
Software\Policies\Microsoft\Windows\DataCollection
AllowTelemetry
DELETE

"@
    Apply-LgpoText $lgpoText
    Write-Host "  DONE." -ForegroundColor Green
}


###############################################################################
#  ROLLBACK MENU
###############################################################################
function Handle-Rollback {
    $rb = Show-RollbackMenu
    switch ($rb) {
        "A" { Rollback-GroupA }
        "B" { Rollback-GroupB }
        "C" { Rollback-GroupC }
        "D" { Rollback-GroupD }
        "E" { Rollback-GroupE }
        "F" { Rollback-GroupF }
        "G" { Rollback-GroupG }
        "H" { Rollback-GroupH }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
    Write-Host ""
    Write-Host "  *** Rollback applied. Run: gpupdate /force  then REBOOT. ***" -ForegroundColor Yellow
}


###############################################################################
#  MAIN LOOP
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "  DISA STIG Incremental Application Tool — Windows 10/11" -ForegroundColor White
Write-Host "  Apply one group, reboot, test, then return for the next." -ForegroundColor DarkGray
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

do {
    $choice = Show-Menu
    switch ($choice) {
        "A" { Apply-GroupA }
        "B" { Apply-GroupB }
        "C" { Apply-GroupC }
        "D" { Apply-GroupD }
        "E" { Apply-GroupE }
        "F" { Apply-GroupF }
        "G" { Apply-GroupG }
        "H" { Apply-GroupH }
        "R" { Handle-Rollback }
        "Q" { Write-Host "  Exiting." -ForegroundColor DarkGray }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
} while ($choice -ne "Q")
