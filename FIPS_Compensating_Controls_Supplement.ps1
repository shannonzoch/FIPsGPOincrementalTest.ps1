#Requires -RunAsAdministrator
###############################################################################
#  FIPS-Exempt Workstation — SUPPLEMENTAL Registry Entries
#  
#  PURPOSE:  Adds ONLY the entries missing from the original script.
#            Run this alongside your existing script, not as a replacement.
#
#  DEPLOY:   - Directly on the workstation (elevated PowerShell), OR
#            - As a GPO Computer Startup Script attached to the workstation OU
#
#  REBOOT:   Required after execution — SCHANNEL changes are not live.
###############################################################################

$base = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

function Set-SCHANNELKey {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    New-Item -Path $Path -Force | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
}

Write-Host "`n[1/6] Adding DisabledByDefault keys for all disabled protocols..." -ForegroundColor Cyan

# Best practice: set both Enabled=0 AND DisabledByDefault=1 for each disabled protocol.
# Some applications and third-party libraries check only DisabledByDefault, ignoring Enabled.
foreach ($proto in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
    foreach ($role in @("Server", "Client")) {
        $p = "$base\Protocols\$proto\$role"
        Set-SCHANNELKey $p "DisabledByDefault" 1
        Write-Host "   SET: $proto\$role -> DisabledByDefault = 1"
    }
}

# Ensure TLS 1.2 is NOT flagged as disabled-by-default (belt-and-suspenders)
foreach ($role in @("Server", "Client")) {
    $p = "$base\Protocols\TLS 1.2\$role"
    Set-SCHANNELKey $p "DisabledByDefault" 0
    Write-Host "   SET: TLS 1.2\$role -> DisabledByDefault = 0"
}

Write-Host "`n[2/6] Enabling TLS 1.3 (Windows 10 1903+ / Server 2022 and later)..." -ForegroundColor Cyan

# TLS 1.3 is the strongest available protocol and must be explicitly enabled.
# On older OS versions this key is ignored harmlessly.
foreach ($role in @("Server", "Client")) {
    $p = "$base\Protocols\TLS 1.3\$role"
    Set-SCHANNELKey $p "Enabled"          1
    Set-SCHANNELKey $p "DisabledByDefault" 0
    Write-Host "   SET: TLS 1.3\$role -> Enabled = 1, DisabledByDefault = 0"
}

Write-Host "`n[3/6] Disabling RC2 cipher family (all bit lengths)..." -ForegroundColor Cyan

# RC2 was omitted from the original script. All variants must be explicitly disabled.
foreach ($rc2 in @("RC2 128/128", "RC2 56/128", "RC2 40/128")) {
    Set-SCHANNELKey "$base\Ciphers\$rc2" "Enabled" 0
    Write-Host "   SET: Ciphers\$rc2 -> Enabled = 0"
}

Write-Host "`n[4/6] Explicitly enabling AES 128 and AES 256 ciphers..." -ForegroundColor Cyan

# CRITICAL: AES is the primary FIPS-approved symmetric cipher.
# After disabling all legacy ciphers, AES must be explicitly permitted.
# Without this, some edge cases (e.g. older IIS app pools, certain .NET stacks)
# may fail to negotiate any cipher at all.
foreach ($aes in @("AES 128/128", "AES 256/256")) {
    Set-SCHANNELKey "$base\Ciphers\$aes" "Enabled" 1
    Write-Host "   SET: Ciphers\$aes -> Enabled = 1"
}

Write-Host "`n[5/6] Enabling SHA384 hash and setting minimum DH key size..." -ForegroundColor Cyan

# SHA384 — completes the SHA-2 family alongside SHA256 and SHA512.
Set-SCHANNELKey "$base\Hashes\SHA384" "Enabled" 1
Write-Host "   SET: Hashes\SHA384 -> Enabled = 1"

# Minimum DH key size — prevents Logjam-style attacks where DH negotiates
# a weak 512 or 1024-bit key. Requires 2048-bit minimum on both sides.
Set-SCHANNELKey "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ServerMinKeyBitLength" 2048
Set-SCHANNELKey "$base\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength" 2048
Write-Host "   SET: KeyExchangeAlgorithms\Diffie-Hellman -> ServerMinKeyBitLength = 2048"
Write-Host "   SET: KeyExchangeAlgorithms\Diffie-Hellman -> ClientMinKeyBitLength = 2048"

Write-Host "`n[6/6] Configuring Cipher Suite Order (strong AES-GCM suites first)..." -ForegroundColor Cyan

# This enforces the same preference order as the GPO Admin Template setting:
#   Computer Config > Admin Templates > Network > SSL Configuration Settings
#   > SSL Cipher Suite Order
#
# TLS 1.3 suites are listed first, followed by TLS 1.2 ECDHE/DHE AES-GCM suites.
# PKCS/RSA key-exchange suites are intentionally omitted here to prefer
# forward-secret key exchange (ECDHE/DHE) wherever possible.

$cipherSuites = @(
    "TLS_AES_256_GCM_SHA384",                    # TLS 1.3
    "TLS_AES_128_GCM_SHA256",                    # TLS 1.3
    "TLS_CHACHA20_POLY1305_SHA256",              # TLS 1.3
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",  # TLS 1.2 — preferred
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",  # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",    # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",    # TLS 1.2
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",      # TLS 1.2 — fallback
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"       # TLS 1.2 — fallback
) -join ","

$cipherRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
New-Item -Path $cipherRegPath -Force | Out-Null
Set-ItemProperty -Path $cipherRegPath -Name "Functions" -Value $cipherSuites -Type String
Write-Host "   SET: SSL\00010002\Functions -> (9 cipher suites configured)"

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  All supplemental entries applied successfully." -ForegroundColor Green
Write-Host "  *** A system restart is required for SCHANNEL changes to take effect. ***" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Green
