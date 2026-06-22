#Requires -RunAsAdministrator
###############################################################################
#  STIG_Revert_All.ps1
#
#  PURPOSE:  Reverts all DISA STIG hardening on a standalone (non-domain)
#            Windows 10/11 workstation back to Windows factory defaults.
#            Uses LGPO.exe where available; falls back to direct methods.
#
#  LGPO.exe: Download from Microsoft Security Compliance Toolkit (SCT):
#            https://www.microsoft.com/en-us/download/details.aspx?id=55319
#            Place LGPO.exe in the same folder as this script, or in a
#            directory listed in $env:PATH.
#
#  WHAT IT REVERTS:
#    [1]  Local Group Policy registry.pol files (all GPO-applied registry)
#    [2]  Security Policy — password, lockout, audit, user rights, LSA options
#    [3]  Advanced Audit Policy (auditpol)
#    [4]  SCHANNEL / TLS / cipher registry keys
#    [5]  .NET Framework strong crypto flags
#    [6]  Administrative Template registry keys (AutoPlay, WER, etc.)
#    [7]  FIPS algorithm policy
#
#  REBOOT REQUIRED: Yes.
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
if ($lgpo) {
    Write-Host "  LGPO.exe found: $lgpo" -ForegroundColor Green
} else {
    Write-Warning "LGPO.exe not found. Registry.pol clearing will use direct file deletion instead."
    Write-Warning "Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319"
}

function Write-Step { param([string]$N,[string]$T)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
    Write-Host "  [$N]  $T" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
}

function Remove-RegKeyIfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "   REMOVED  $Path" -ForegroundColor Gray
    } else {
        Write-Host "   SKIPPED  (not present)  $Path" -ForegroundColor DarkGray
    }
}

function Remove-RegValueIfExists {
    param([string]$Path,[string]$Name)
    if ((Test-Path $Path) -and (Get-ItemProperty $Path -Name $Name -ErrorAction SilentlyContinue)) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        Write-Host "   REMOVED  $Name  |  $Path" -ForegroundColor Gray
    } else {
        Write-Host "   SKIPPED  (not present)  $Name  |  $Path" -ForegroundColor DarkGray
    }
}

function Set-RegDWord {
    param([string]$Path,[string]$Name,[int]$Value)
    New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Write-Host "   SET  $Name = $Value  |  $Path" -ForegroundColor Gray
}


###############################################################################
#  STEP 1 — Clear Local Group Policy (Registry.pol)
###############################################################################
Write-Step "1/7" "Clearing Local Group Policy (Registry.pol)"

$polPaths = @(
    "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol",
    "$env:SystemRoot\System32\GroupPolicy\User\Registry.pol",
    "$env:SystemRoot\System32\GroupPolicyUsers"
)

if ($lgpo) {
    # Build an empty LGPO text file — applying it clears all GPO registry settings
    $emptyLgpo = "$env:TEMP\lgpo_clear.txt"
    Set-Content -Path $emptyLgpo -Value "; Empty LGPO — clears all local GPO registry settings`r`nComputer`r`n`r`nUser`r`n"
    & $lgpo /t $emptyLgpo /q
    Remove-Item $emptyLgpo -Force -ErrorAction SilentlyContinue
    Write-Host "   LGPO applied empty policy — registry.pol reset." -ForegroundColor Gray
} else {
    # Direct deletion — equivalent result
    foreach ($pol in $polPaths) {
        if (Test-Path $pol) {
            # For the GroupPolicyUsers folder, only clear contents, don't delete folder
            if ($pol -like "*GroupPolicyUsers") {
                Get-ChildItem $pol -Recurse -File | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Host "   CLEARED  $pol" -ForegroundColor Gray
            } else {
                Remove-Item $pol -Force -ErrorAction SilentlyContinue
                Write-Host "   REMOVED  $pol" -ForegroundColor Gray
            }
        }
    }
}

Write-Host "   DONE: Local GPO registry cleared." -ForegroundColor Green


###############################################################################
#  STEP 2 — Reset Security Policy to Windows Defaults (secedit)
#           Covers: Password policy, lockout, audit, user rights, LSA options
###############################################################################
Write-Step "2/7" "Resetting Security Policy to Windows Defaults (secedit)"

# defltbase.inf is Windows' built-in default security template
$defltBase  = "$env:SystemRoot\inf\defltbase.inf"
$seceditDb  = "$env:TEMP\stig_revert_secedit.sdb"
$seceditLog = "$env:TEMP\stig_revert_secedit.log"

if (Test-Path $defltBase) {
    # Remove old temp database if present
    Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue

    secedit /configure `
        /db  $seceditDb `
        /cfg $defltBase `
        /overwrite `
        /quiet

    Write-Host "   secedit applied defltbase.inf successfully." -ForegroundColor Gray
} else {
    Write-Warning "defltbase.inf not found at $defltBase — skipping secedit reset."
    Write-Warning "You may need to manually reset security policy via: secpol.msc"
}

# Additionally write a custom INF that explicitly zeros out key STIG settings
# that defltbase.inf may leave ambiguous
$resetInf = @"
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
EnableAdminAccount = 1
EnableGuestAccount = 0
[Event Audit]
AuditSystemEvents = 0
AuditLogonEvents = 0
AuditObjectAccess = 0
AuditPrivilegeUse = 0
AuditPolicyChange = 0
AuditAccountManage = 0
AuditProcessTracking = 0
AuditDSAccess = 0
AuditAccountLogon = 0
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,3
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyNetworkLogonRight =
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyInteractiveLogonRight =
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyRemoteInteractiveLogonRight =
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDebugPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeTcbPrivilege =
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeCreatePermanentPrivilege =
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege =
SeSecurityPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeMachineAccountPrivilege =
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
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

$resetInfPath = "$env:TEMP\stig_revert_custom.inf"
$resetDbPath  = "$env:TEMP\stig_revert_custom.sdb"
Set-Content -Path $resetInfPath -Value $resetInf -Encoding Unicode

Remove-Item $resetDbPath -Force -ErrorAction SilentlyContinue
secedit /configure /db $resetDbPath /cfg $resetInfPath /overwrite /quiet
Remove-Item $resetInfPath,$resetDbPath -Force -ErrorAction SilentlyContinue

Write-Host "   DONE: Security policy reset to defaults." -ForegroundColor Green


###############################################################################
#  STEP 3 — Reset Advanced Audit Policy (auditpol)
###############################################################################
Write-Step "3/7" "Resetting Advanced Audit Policy (auditpol)"

# Clear all advanced audit settings back to 'No Auditing'
auditpol /clear /y | Out-Null

# Restore the handful of audits Windows enables by default
auditpol /set /subcategory:"Credential Validation"          /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logon"                          /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff"                         /success:enable               | Out-Null
auditpol /set /subcategory:"Account Lockout"                /failure:enable               | Out-Null
auditpol /set /subcategory:"Special Logon"                  /success:enable               | Out-Null

Write-Host "   DONE: Audit policy cleared and Windows defaults restored." -ForegroundColor Green


###############################################################################
#  STEP 4 — Remove SCHANNEL / TLS / Cipher Registry Keys
###############################################################################
Write-Step "4/7" "Removing SCHANNEL/TLS/Cipher hardening keys"

$schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Protocols — remove all subkeys (returns to OS built-in defaults)
foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
    foreach ($role in @("Server","Client")) {
        Remove-RegKeyIfExists "$schannel\Protocols\$proto\$role"
    }
    $pp = "$schannel\Protocols\$proto"
    if ((Test-Path $pp) -and -not (Get-ChildItem $pp -ErrorAction SilentlyContinue)) {
        Remove-Item $pp -Force -ErrorAction SilentlyContinue
    }
}

# Ciphers
foreach ($c in @("AES 128/128","AES 256/256","RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
                  "RC2 128/128","RC2 56/128","RC2 40/128","DES 56/56","Triple DES 168","NULL")) {
    Remove-RegKeyIfExists "$schannel\Ciphers\$c"
}

# Hashes
foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
    Remove-RegKeyIfExists "$schannel\Hashes\$h"
}

# Key Exchange Algorithms — remove only the values we added, not the whole key
foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
    $kxPath = "$schannel\KeyExchangeAlgorithms\$kx"
    Remove-RegValueIfExists $kxPath "Enabled"
    Remove-RegValueIfExists $kxPath "ServerMinKeyBitLength"
    Remove-RegValueIfExists $kxPath "ClientMinKeyBitLength"
}

Write-Host "   DONE: SCHANNEL keys removed — OS built-in defaults restored." -ForegroundColor Green


###############################################################################
#  STEP 5 — Remove .NET Framework Strong Crypto Flags
###############################################################################
Write-Step "5/7" "Removing .NET SchUseStrongCrypto flags"

foreach ($v in @("v4.0.30319","v2.0.50727")) {
    foreach ($hive in @("SOFTWARE\Microsoft\.NETFramework","SOFTWARE\Wow6432Node\Microsoft\.NETFramework")) {
        Remove-RegValueIfExists "HKLM:\$hive\$v" "SchUseStrongCrypto"
    }
}
Write-Host "   DONE." -ForegroundColor Green


###############################################################################
#  STEP 6 — Remove Administrative Template Registry Keys (STIG-applied)
###############################################################################
Write-Step "6/7" "Removing STIG Administrative Template registry settings"

# Cipher suite order (SSL Configuration Settings GPO)
Remove-RegValueIfExists `
    "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "Functions"

# AutoPlay / AutoRun
Remove-RegValueIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"                 "NoAutoplayfornonVolume"

# Windows Error Reporting
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"  "Disabled"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"          "DoReport"

# Remote Desktop / RDP
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptionLevelMatch"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableEncryption"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"

# Windows Defender / SmartScreen
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"                    "EnableSmartScreen"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"                    "ShellSmartScreenLevel"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"      "EnabledV9"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"  "Enabled"

# Telemetry / Data Collection
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"

# Indexing / Search
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems"

# Credential Delegation (CredSSP)
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"

# PowerShell script block logging
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"

# Early Launch Anti-Malware
Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"

# Windows Installer elevation
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
Remove-RegValueIfExists "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"

# Solicited Remote Assistance
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"

# Safe DLL search
Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"

# WDigest
Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"

# LSASS protection
Remove-RegValueIfExists "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"

# DCOM
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" "MachineAccessRestriction"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" "MachineLaunchRestriction"

# Attachment Manager (dangerous file handling)
Remove-RegValueIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" "DefaultFileTypeRisk"
Remove-RegValueIfExists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"  "SaveZoneInformation"

# Microsoft Support Diagnostic Tool (MSDT)
Remove-RegValueIfExists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer"

Write-Host "   DONE: Administrative template registry keys removed." -ForegroundColor Green


###############################################################################
#  STEP 7 — Reset FIPS Policy and Force Group Policy Refresh
###############################################################################
Write-Step "7/7" "Resetting FIPS policy and refreshing Group Policy"

# FIPS — set back to disabled (our working state from previous scripts)
# Change Value to 1 if you want to restore FIPS fully enabled
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" "Enabled" 0
Write-Host "   NOTE: FIPS left as DISABLED (0). Change to 1 if full revert is needed." -ForegroundColor Yellow

# Force Group Policy refresh to pick up registry.pol changes
Write-Host "   Running gpupdate /force..." -ForegroundColor Gray
gpupdate /force /quiet 2>&1 | Out-Null

Write-Host "   DONE." -ForegroundColor Green


###############################################################################
#  SUMMARY
###############################################################################
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  REVERT COMPLETE" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  [1] Local GPO registry.pol  — cleared"
Write-Host "  [2] Security policy         — reset to Windows defaults"
Write-Host "  [3] Advanced audit policy   — cleared"
Write-Host "  [4] SCHANNEL/TLS keys       — removed (OS defaults restored)"
Write-Host "  [5] .NET strong crypto      — removed"
Write-Host "  [6] Admin template keys     — removed"
Write-Host "  [7] FIPS                    — left DISABLED (per your requirement)"
Write-Host ""
Write-Host "  *** REBOOT REQUIRED for all changes to take effect. ***" -ForegroundColor Yellow
Write-Host ""

$r = Read-Host "Restart now? (Y/N)"
if ($r -match "^[Yy]$") { Start-Sleep 5; Restart-Computer -Force }
else { Write-Host "  Restart skipped. Reboot before testing." -ForegroundColor Yellow }
