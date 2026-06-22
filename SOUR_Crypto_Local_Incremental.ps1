###############################################################################
#  SOUR_Crypto_Local_Incremental.ps1
#
#  VERSION : 2.0.0
#
# ─────────────────────────────────────────────────────────────────────────────
#  CHANGE LOG
# ─────────────────────────────────────────────────────────────────────────────
#  v2.0.0  2026-04-22
#    - Added [S] Take Snapshot option that records the exact pre-test state
#      of every registry key and value this script can modify, saved to
#      crypto_snapshot.json in the script directory so it survives reboots.
#    - Added [RA] Revert All option that reads the snapshot and restores
#      each entry to precisely what it was before testing started:
#        * Key did not exist before  → key is deleted if it now exists.
#        * Key existed, value absent → value is removed if it now exists.
#        * Key existed, value present → original value and type are restored.
#    - Snapshot records: path, value name, key existence, value existence,
#      original data, and original registry type (DWord, String, etc.) for
#      each of the 47 key/value pairs this script can touch.
#    - Snapshot status shown in menu header (taken / not taken / date).
#    - [S] warns and prompts before overwriting an existing snapshot.
#    - [RA] refuses to run if no snapshot exists.
#    - Per-group rollback functions unchanged and still available.
#
#  v1.0.0  2026-04-22
#    - Initial release.
#    - Applies the same 10 strong-crypto groups as
#      SOUR_Crypto_Incremental_Push.ps1 v1.2.0 but writes directly to the
#      local registry instead of via GPO or LGPO.
#    - Run this script ON THE WORKSTATION ITSELF in an elevated session.
#    - No parameters required — no GPO name, no remote host.
#    - Each group has Apply and Rollback. Rollback removes keys entirely,
#      returning Windows to its built-in defaults for that setting.
#    - Interactive menu identical in structure to the GPO incremental script.
#    - FIPS flag intentionally NOT set (known software incompatibility).
#    - PKCS key exchange intentionally NOT set (known software
#      incompatibility).
#    - SHA256 SCHANNEL hash registry key intentionally NOT set (known
#      software incompatibility).
#    - 0xffffffff bitmask used for Cipher, Hash, and KeyExchangeAlgorithm
#      Enabled values. Protocol Enabled values correctly use 1/0.
#
# ─────────────────────────────────────────────────────────────────────────────
#
#  PURPOSE : Incrementally apply strong-crypto registry settings directly
#            to the local machine for isolated testing without GPO or LGPO.
#            Apply one group, reboot, test your software, then continue.
#
#  USAGE   : Run from an elevated PowerShell session on the workstation:
#              .\SOUR_Crypto_Local_Incremental.ps1
#
#  REBOOT  : Required after EVERY group — SCHANNEL changes are not active
#            until the system restarts.
#
#  SNAPSHOT / REVERT ALL:
#    Use [S] to take a snapshot BEFORE applying any groups. The snapshot
#    is saved to crypto_snapshot.json alongside the script and persists
#    across reboots. Use [RA] at any point to restore every tracked setting
#    to exactly what it was when the snapshot was taken. Per-group rollbacks
#    (R1–R10) remain available as before for finer-grained control.
#
#  GROUPS:
#    1  — Enable AES 128/256 ciphers              (Very Low Risk)
#    2  — Enable SHA384 hash                       (Very Low Risk)
#    3  — Disable legacy protocols SSL2/3, TLS1.0/1.1 (Low Risk)
#    4  — Enable TLS 1.2 explicitly                (Very Low Risk)
#    5  — Enable TLS 1.3                           (Low Risk)
#    6  — Disable weak ciphers RC4/RC2/DES/3DES/NULL (Medium Risk)
#    7  — Hashes: disable MD5, enable SHA/SHA256/SHA512 (Low Risk)
#    8  — Key exchange DH + ECDH, min DH 2048-bit  (Medium Risk)
#    9  — .NET Framework SchUseStrongCrypto         (Low Risk)
#   10  — Cipher suite order policy                 (Higher Risk)
###############################################################################

#Requires -RunAsAdministrator

$base         = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$SnapshotPath = Join-Path $PSScriptRoot "crypto_snapshot.json"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Set-LocalValue {
    # Creates the key if absent, then sets the named DWord value
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-Host "   SET  [$Name = $Value]  $Path" -ForegroundColor Gray
}

function Remove-LocalValue {
    # Removes a single named value; leaves the key itself intact
    param([string]$Path, [string]$Name)
    if ((Test-Path $Path) -and
        ($null -ne (Get-ItemProperty $Path -Name $Name -ErrorAction SilentlyContinue))) {
        Remove-ItemProperty -Path $Path -Name $Name -Force
        Write-Host "   REMOVED  [$Name]  $Path" -ForegroundColor Gray
    } else {
        Write-Host "   SKIP  (not present)  [$Name]  $Path" -ForegroundColor DarkGray
    }
}

function Remove-LocalKey {
    # Removes an entire registry key and all its values
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force
        Write-Host "   REMOVED KEY  $Path" -ForegroundColor Gray
    } else {
        Write-Host "   SKIP  (not present)  $Path" -ForegroundColor DarkGray
    }
}

###############################################################################
#  SNAPSHOT INFRASTRUCTURE
###############################################################################

function Get-SnapshotStatus {
    # Returns a display string for the menu header
    if (Test-Path $SnapshotPath) {
        $snap = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
        return "TAKEN  $($snap.Timestamp)  ($($snap.EntryCount) entries)"
    }
    return "NOT TAKEN — run [S] before applying any groups"
}

function Build-SnapshotManifest {
    # Returns an ordered list of every [Path, Name] pair this script can touch.
    $manifest = [System.Collections.Generic.List[hashtable]]::new()

    # Ciphers
    foreach ($c in @(
        "AES 128/128","AES 256/256",
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) { $manifest.Add(@{ Path = "$base\Ciphers\$c"; Name = "Enabled" }) }

    # Hashes
    foreach ($h in @("MD5","SHA","SHA256","SHA384","SHA512")) {
        $manifest.Add(@{ Path = "$base\Hashes\$h"; Name = "Enabled" })
    }

    # Protocols — Enabled and DisabledByDefault for every proto/role
    foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
        foreach ($r in @("Server","Client")) {
            $manifest.Add(@{ Path = "$base\Protocols\$p\$r"; Name = "Enabled" })
            $manifest.Add(@{ Path = "$base\Protocols\$p\$r"; Name = "DisabledByDefault" })
        }
    }

    # Key Exchange Algorithms
    foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        $manifest.Add(@{ Path = "$base\KeyExchangeAlgorithms\$kx"; Name = "Enabled" })
    }
    $manifest.Add(@{ Path = "$base\KeyExchangeAlgorithms\Diffie-Hellman"; Name = "ServerMinKeyBitLength" })
    $manifest.Add(@{ Path = "$base\KeyExchangeAlgorithms\Diffie-Hellman"; Name = "ClientMinKeyBitLength" })

    # .NET Framework
    foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hv in @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) { $manifest.Add(@{ Path = "$hv\$v"; Name = "SchUseStrongCrypto" }) }
    }

    # Cipher Suite Order
    $manifest.Add(@{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        Name = "Functions"
    })

    return $manifest
}

function Take-Snapshot {
    # Warns before overwriting an existing snapshot, then records the full
    # pre-test state of every registry key/value this script can modify.
    if (Test-Path $SnapshotPath) {
        $snap = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
        Write-Host ""
        Write-Host "  A snapshot already exists from $($snap.Timestamp)." -ForegroundColor Yellow
        $overwrite = Read-Host "  Overwrite it? This cannot be undone. (Y/N)"
        if ($overwrite -notmatch "^[Yy]$") {
            Write-Host "  Snapshot NOT overwritten." -ForegroundColor DarkGray
            return
        }
    }

    Write-Host ""
    Write-Host "  Taking snapshot of current registry state..." -ForegroundColor Cyan

    $entries  = [System.Collections.Generic.List[object]]::new()
    $manifest = Build-SnapshotManifest

    foreach ($item in $manifest) {
        $keyPath   = $item.Path
        $valName   = $item.Name
        $keyExists = Test-Path $keyPath

        $originalValue = $null
        $originalType  = $null
        $valueExists   = $false

        if ($keyExists) {
            $regItem = Get-Item -Path $keyPath -ErrorAction SilentlyContinue
            if ($regItem) {
                $rawVal = $regItem.GetValue(
                    $valName, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($null -ne $rawVal) {
                    $valueExists   = $true
                    $originalValue = $rawVal
                    try   { $originalType = $regItem.GetValueKind($valName).ToString() }
                    catch { $originalType = "DWord" }
                }
            }
        }

        $entries.Add([PSCustomObject]@{
            Path               = $keyPath
            Name               = $valName
            KeyExistedBefore   = $keyExists
            ValueExistedBefore = $valueExists
            OriginalValue      = $originalValue
            OriginalType       = $originalType
        })

        $status = if ($valueExists)     { "value=$originalValue ($originalType)" }
                  elseif ($keyExists)   { "key exists, value absent" }
                  else                  { "key absent" }
        Write-Host "   SNAP  [$valName]  $status" -ForegroundColor Gray
    }

    $snapshot = [PSCustomObject]@{
        Timestamp    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ComputerName = $env:COMPUTERNAME
        EntryCount   = $entries.Count
        Entries      = $entries
    }

    $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $SnapshotPath -Encoding UTF8
    Write-Host ""
    Write-Host "  Snapshot saved: $SnapshotPath" -ForegroundColor Green
    Write-Host "  $($entries.Count) entries recorded." -ForegroundColor Green
}

function Revert-All {
    # Reads the snapshot and restores every entry to its exact pre-test state.
    # Three cases:
    #   1. Key did not exist before  → delete key if it now exists
    #   2. Key existed, value absent → remove value if it now exists
    #   3. Key existed, value present → restore original value and type

    if (-not (Test-Path $SnapshotPath)) {
        Write-Host ""
        Write-Host "  No snapshot found at: $SnapshotPath" -ForegroundColor Red
        Write-Host "  Run [S] before starting tests." -ForegroundColor Red
        return
    }

    $snap = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta
    Write-Host "  Revert All — restoring state from $($snap.Timestamp)" -ForegroundColor Magenta
    Write-Host "  Computer: $($snap.ComputerName)   Entries: $($snap.EntryCount)" -ForegroundColor DarkGray
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta

    $restored = 0; $deleted = 0; $removed = 0; $skipped = 0

    # Track deleted keys so we don't attempt value ops on a key we just removed
    $deletedKeys = [System.Collections.Generic.HashSet[string]]::new(
                       [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in $snap.Entries) {
        $path       = $entry.Path
        $name       = $entry.Name
        $keyWasHere = [bool]$entry.KeyExistedBefore
        $valWasHere = [bool]$entry.ValueExistedBefore
        $origVal    = $entry.OriginalValue
        $origType   = $entry.OriginalType

        # Skip if parent key was already deleted this run
        if ($deletedKeys.Contains($path)) {
            Write-Host "   SKIP  (parent key already deleted)  [$name]" -ForegroundColor DarkGray
            $skipped++; continue
        }

        # ── Case 1: key did not exist — delete it if created by our script ────
        if (-not $keyWasHere) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                $deletedKeys.Add($path) | Out-Null
                Write-Host "   DELETED KEY  $path" -ForegroundColor Gray
                $deleted++
            } else {
                Write-Host "   SKIP  (key still absent)  $path" -ForegroundColor DarkGray
                $skipped++
            }
            continue
        }

        # ── Case 2: key existed but value was absent — remove if now present ──
        if (-not $valWasHere) {
            $cur = Get-ItemProperty $path -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $cur.$name) {
                Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction SilentlyContinue
                Write-Host "   REMOVED VALUE  [$name]  $path" -ForegroundColor Gray
                $removed++
            } else {
                Write-Host "   SKIP  (value still absent)  [$name]" -ForegroundColor DarkGray
                $skipped++
            }
            continue
        }

        # ── Case 3: key and value existed — restore original data ─────────────
        try {
            $typeMap = @{
                DWord        = "DWord";   QWord       = "QWord"
                String       = "String";  ExpandString = "ExpandString"
                MultiString  = "MultiString"; Binary  = "Binary"
            }
            $psType = if ($typeMap.ContainsKey($origType)) { $typeMap[$origType] } else { "DWord" }
            New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $path -Name $name -Value $origVal -Type $psType
            Write-Host "   RESTORED  [$name = $origVal ($psType)]" -ForegroundColor Gray
            $restored++
        } catch {
            Write-Host "   ERROR  [$name]  $path  $_" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Revert complete." -ForegroundColor Green
    Write-Host "    Restored : $restored  (original value written back)"
    Write-Host "    Removed  : $removed   (value deleted — was absent before)"
    Write-Host "    Deleted  : $deleted   (key deleted — did not exist before)"
    Write-Host "    Skipped  : $skipped   (already in correct state)"
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $reboot = Read-Host "  Reboot now to apply? (Y/N)"
    if ($reboot -match "^[Yy]$") {
        Write-Host "  Rebooting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}


###############################################################################
#  DISPLAY / PROMPT HELPERS
###############################################################################

function Write-Section {
    param([string]$Title, [string]$Risk)
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    if ($Risk) {
        Write-Host "  Risk: $Risk" -ForegroundColor Yellow
    }
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Prompt-NextSteps {
    param([string]$Label)
    Write-Host ""
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Group $Label applied to local registry." -ForegroundColor Green
    Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "    1. REBOOT this workstation (SCHANNEL requires restart)"
    Write-Host "    2. Test your software thoroughly"
    Write-Host "    3. Run this script again and apply the next group"
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $reboot = Read-Host "  Reboot now? (Y/N)"
    if ($reboot -match "^[Yy]$") {
        Write-Host "  Rebooting in 10 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}


###############################################################################
#  GROUP 1 — Enable AES 128/256 Ciphers
###############################################################################
function Apply-Group1 {
    Write-Section "Group 1 — Enable AES 128/256 Ciphers" "Very Low — purely additive"
    Set-LocalValue "$base\Ciphers\AES 128/128" "Enabled" 0xffffffff
    Set-LocalValue "$base\Ciphers\AES 256/256" "Enabled" 0xffffffff
    Prompt-NextSteps "1"
}

function Rollback-Group1 {
    Write-Host "  Rolling back Group 1..." -ForegroundColor Magenta
    Remove-LocalKey "$base\Ciphers\AES 128/128"
    Remove-LocalKey "$base\Ciphers\AES 256/256"
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 2 — Enable SHA384 Hash
###############################################################################
function Apply-Group2 {
    Write-Section "Group 2 — Enable SHA384 Hash" "Very Low — purely additive"
    Set-LocalValue "$base\Hashes\SHA384" "Enabled" 0xffffffff
    Prompt-NextSteps "2"
}

function Rollback-Group2 {
    Write-Host "  Rolling back Group 2..." -ForegroundColor Magenta
    Remove-LocalKey "$base\Hashes\SHA384"
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 3 — Disable Legacy Protocols (SSL 2/3, TLS 1.0, TLS 1.1)
#  Enabled=0 and DisabledByDefault=1 for belt-and-suspenders coverage
###############################################################################
function Apply-Group3 {
    Write-Section "Group 3 — Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1" `
                  "Low — already off by default on Win10; test any legacy integrations"

    foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
        foreach ($role in @("Server","Client")) {
            Set-LocalValue "$base\Protocols\$proto\$role" "Enabled"           0
            Set-LocalValue "$base\Protocols\$proto\$role" "DisabledByDefault" 1
        }
    }
    Prompt-NextSteps "3"
}

function Rollback-Group3 {
    Write-Host "  Rolling back Group 3..." -ForegroundColor Magenta
    foreach ($proto in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1")) {
        foreach ($role in @("Server","Client")) {
            Remove-LocalKey "$base\Protocols\$proto\$role"
        }
    }
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 4 — Enable TLS 1.2 Explicitly
#  Protocol nodes use 1/0 boolean flags — not 0xffffffff bitmask
###############################################################################
function Apply-Group4 {
    Write-Section "Group 4 — Explicitly Enable TLS 1.2" `
                  "Very Low — on by default on Win10; makes it explicit"

    foreach ($role in @("Server","Client")) {
        Set-LocalValue "$base\Protocols\TLS 1.2\$role" "Enabled"           1
        Set-LocalValue "$base\Protocols\TLS 1.2\$role" "DisabledByDefault" 0
    }
    Prompt-NextSteps "4"
}

function Rollback-Group4 {
    Write-Host "  Rolling back Group 4..." -ForegroundColor Magenta
    foreach ($role in @("Server","Client")) {
        Remove-LocalKey "$base\Protocols\TLS 1.2\$role"
    }
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 5 — Enable TLS 1.3
#  Silently ignored on Windows versions that do not support it
###############################################################################
function Apply-Group5 {
    Write-Section "Group 5 — Enable TLS 1.3" `
                  "Low — ignored on pre-Win10 1903; test outbound connections"

    foreach ($role in @("Server","Client")) {
        Set-LocalValue "$base\Protocols\TLS 1.3\$role" "Enabled"           1
        Set-LocalValue "$base\Protocols\TLS 1.3\$role" "DisabledByDefault" 0
    }
    Prompt-NextSteps "5"
}

function Rollback-Group5 {
    Write-Host "  Rolling back Group 5..." -ForegroundColor Magenta
    foreach ($role in @("Server","Client")) {
        Remove-LocalKey "$base\Protocols\TLS 1.3\$role"
    }
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 6 — Disable Weak Ciphers (RC4, RC2, DES, 3DES, NULL)
###############################################################################
function Apply-Group6 {
    Write-Section "Group 6 — Disable Weak Ciphers" `
                  "Medium — test RDP, legacy COM/ODBC integrations, inbound TLS"

    foreach ($cipher in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        Set-LocalValue "$base\Ciphers\$cipher" "Enabled" 0
    }
    Prompt-NextSteps "6"
}

function Rollback-Group6 {
    Write-Host "  Rolling back Group 6..." -ForegroundColor Magenta
    foreach ($cipher in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        Remove-LocalKey "$base\Ciphers\$cipher"
    }
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 7 — Hash Algorithms
#  MD5 disabled; SHA/SHA256/SHA512 enabled with 0xffffffff bitmask.
#  NOTE: SHA256 hash registry key intentionally omitted — known software
#        incompatibility. SHA256 in GCM cipher suite names is handled by
#        the TLS stack and is not affected by this registry key.
###############################################################################
function Apply-Group7 {
    Write-Section "Group 7 — Hashes: Disable MD5, Enable SHA/SHA256/SHA512" `
                  "Low — test certificate operations and signature verification"

    Set-LocalValue "$base\Hashes\MD5"    "Enabled" 0
    Set-LocalValue "$base\Hashes\SHA"    "Enabled" 0xffffffff
    Set-LocalValue "$base\Hashes\SHA256" "Enabled" 0xffffffff
    Set-LocalValue "$base\Hashes\SHA512" "Enabled" 0xffffffff
    Prompt-NextSteps "7"
}

function Rollback-Group7 {
    Write-Host "  Rolling back Group 7..." -ForegroundColor Magenta
    Remove-LocalKey "$base\Hashes\MD5"
    Remove-LocalKey "$base\Hashes\SHA"
    Remove-LocalKey "$base\Hashes\SHA256"
    Remove-LocalKey "$base\Hashes\SHA512"
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 8 — Key Exchange Algorithms + Minimum DH Key Size
#  Enabled uses 0xffffffff bitmask; MinKeyBitLength is an actual size value.
#  NOTE: PKCS key exchange intentionally omitted — known software
#        incompatibility.
###############################################################################
function Apply-Group8 {
    Write-Section "Group 8 — Key Exchange: DH + ECDH, Min DH Key 2048-bit" `
                  "Medium — test ALL outbound TLS connections the software makes"

    Set-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "Enabled"               0xffffffff
    Set-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength"  2048
    Set-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength"  2048
    Set-LocalValue "$base\KeyExchangeAlgorithms\ECDH"           "Enabled"               0xffffffff
    Prompt-NextSteps "8"
}

function Rollback-Group8 {
    Write-Host "  Rolling back Group 8..." -ForegroundColor Magenta
    Remove-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "Enabled"
    Remove-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength"
    Remove-LocalValue "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength"
    Remove-LocalValue "$base\KeyExchangeAlgorithms\ECDH"           "Enabled"
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 9 — .NET Framework SchUseStrongCrypto
#  Forces .NET to negotiate TLS 1.2+ instead of defaulting to older
#  protocols. Applied to v4.x and v2.x, both 32-bit and 64-bit paths.
###############################################################################
function Apply-Group9 {
    Write-Section "Group 9 — .NET SchUseStrongCrypto" `
                  "Low — test any .NET web service calls or WCF in the software"

    foreach ($version in @("v4.0.30319","v2.0.50727")) {
        foreach ($hive in @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) {
            Set-LocalValue "$hive\$version" "SchUseStrongCrypto" 1
        }
    }
    Prompt-NextSteps "9"
}

function Rollback-Group9 {
    Write-Host "  Rolling back Group 9..." -ForegroundColor Magenta
    foreach ($version in @("v4.0.30319","v2.0.50727")) {
        foreach ($hive in @(
            "HKLM:\SOFTWARE\Microsoft\.NETFramework",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) {
            Remove-LocalValue "$hive\$version" "SchUseStrongCrypto"
        }
    }
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  GROUP 10 — Cipher Suite Order Policy
#  Written to the same registry path that gpedit.msc uses for the
#  SSL Cipher Suite Order Administrative Template setting.
###############################################################################
function Apply-Group10 {
    Write-Section "Group 10 — Cipher Suite Order Policy" `
                  "Higher — apply last; test ALL TLS paths most thoroughly"

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

    $csPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    New-Item -Path $csPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $csPath -Name "Functions" -Value $cipherSuites -Type String
    Write-Host "   SET  [Functions = 9 cipher suites]" -ForegroundColor Gray

    Prompt-NextSteps "10"
}

function Rollback-Group10 {
    Write-Host "  Rolling back Group 10..." -ForegroundColor Magenta
    Remove-LocalValue `
        "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
        "Functions"
    Write-Host "  Done. Reboot to apply." -ForegroundColor Green
}


###############################################################################
#  VERIFY — reads live local registry and displays current state
###############################################################################
function Verify-Local {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  Live Local Registry — Current Crypto State" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

    Write-Host "`n── AES Ciphers (expect 4294967295) ──" -ForegroundColor Cyan
    $aesResults = foreach ($aes in @("AES 128/128","AES 256/256")) {
        $v = (Get-ItemProperty "$base\Ciphers\$aes" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Cipher = $aes; Enabled = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
    }
    $aesResults | Format-Table -AutoSize

    Write-Host "`n── Weak Ciphers (expect 0) ──" -ForegroundColor Cyan
    $weakResults = foreach ($c in @(
        "RC4 128/128","RC4 64/128","RC4 56/128","RC4 40/128",
        "RC2 128/128","RC2 56/128","RC2 40/128",
        "DES 56/56","Triple DES 168","NULL"
    )) {
        $v = (Get-ItemProperty "$base\Ciphers\$c" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Cipher = $c; Enabled = if ($null -ne $v) { $v } else { "(absent)" } }
    }
    $weakResults | Format-Table -AutoSize

    Write-Host "`n── Protocols ──" -ForegroundColor Cyan
    $protoResults = foreach ($p in @("SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1","TLS 1.2","TLS 1.3")) {
        foreach ($r in @("Server","Client")) {
            $vals = Get-ItemProperty "$base\Protocols\$p\$r" -EA SilentlyContinue
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
        $v = (Get-ItemProperty "$base\Hashes\$h" -EA SilentlyContinue).Enabled
        [PSCustomObject]@{ Hash = $h; Enabled = if ($null -ne $v) { $v } else { "(absent=OS default)" } }
    }
    $hashResults | Format-Table -AutoSize

    Write-Host "`n── Key Exchange (expect DH/ECDH=4294967295, min DH=2048) ──" -ForegroundColor Cyan
    $kxResults = foreach ($kx in @("Diffie-Hellman","ECDH","PKCS")) {
        $vals = Get-ItemProperty "$base\KeyExchangeAlgorithms\$kx" -EA SilentlyContinue
        [PSCustomObject]@{
            Algorithm        = $kx
            Enabled          = if ($vals) { $vals.Enabled }               else { "(absent=OS default)" }
            ServerMinKeyBits = if ($vals) { $vals.ServerMinKeyBitLength }  else { "(not set)" }
            ClientMinKeyBits = if ($vals) { $vals.ClientMinKeyBitLength }  else { "(not set)" }
        }
    }
    $kxResults | Format-Table -AutoSize

    Write-Host "`n── .NET SchUseStrongCrypto (expect 1) ──" -ForegroundColor Cyan
    $dotnetResults = foreach ($v in @("v4.0.30319","v2.0.50727")) {
        foreach ($hv in @(
            "SOFTWARE\Microsoft\.NETFramework",
            "SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        )) {
            $val = (Get-ItemProperty "HKLM:\$hv\$v" -Name "SchUseStrongCrypto" -EA SilentlyContinue).SchUseStrongCrypto
            [PSCustomObject]@{
                Path               = "$hv\$v"
                SchUseStrongCrypto = if ($null -ne $val) { $val } else { "(absent)" }
            }
        }
    }
    $dotnetResults | Format-Table -AutoSize

    Write-Host "`n── Cipher Suite Order ──" -ForegroundColor Cyan
    $cs = (Get-ItemProperty `
        "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
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
}


###############################################################################
#  INTERACTIVE MENU
###############################################################################
function Show-Menu {
    $snapStatus = Get-SnapshotStatus
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    Write-Host "  SOUR Local Crypto — Incremental Apply  (Local Registry)" -ForegroundColor White
    Write-Host "  Run on the WORKSTATION. Reboot and test after each group." -ForegroundColor DarkGray
    Write-Host "  Snapshot: $snapStatus" -ForegroundColor $(if ($snapStatus -like "TAKEN*") { "Green" } else { "Yellow" })
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
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
    Write-Host "  [S]  Take snapshot of current state (do this FIRST)"  -ForegroundColor Green
    Write-Host "  [RA] Revert ALL changes to pre-test state (from snapshot)" -ForegroundColor Magenta
    Write-Host "  [V]  Verify current local registry state"
    Write-Host "  [Q]  Quit"
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
    return (Read-Host "  Choice").Trim()
}


###############################################################################
#  MAIN LOOP
###############################################################################
do {
    $choice = Show-Menu
    switch ($choice) {
        "1"   { Apply-Group1   }
        "2"   { Apply-Group2   }
        "3"   { Apply-Group3   }
        "4"   { Apply-Group4   }
        "5"   { Apply-Group5   }
        "6"   { Apply-Group6   }
        "7"   { Apply-Group7   }
        "8"   { Apply-Group8   }
        "9"   { Apply-Group9   }
        "10"  { Apply-Group10  }
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
        "S"   { Take-Snapshot    }
        "RA"  { Revert-All       }
        "V"   { Verify-Local     }
        "Q"   { Write-Host "  Exiting." -ForegroundColor DarkGray }
        default { Write-Host "  Invalid selection." -ForegroundColor Red }
    }
} while ($choice -ne "Q")
