###############################################################################
#  Script 2 of 2 — Recommended Additional Policies (One-Liner Test File)
#
#  PURPOSE: Each line below is a self-contained policy not included in your
#           original script. Run them ONE AT A TIME, then reboot and test
#           your software after each one before proceeding to the next.
#
#  HOW TO USE:
#    1. Open an elevated PowerShell session
#    2. Copy and paste ONE line at a time
#    3. Reboot:  Restart-Computer -Force
#    4. Test your software
#    5. If software still works, return here and apply the next line
#    6. If software breaks, identify which line caused it — that setting
#       is incompatible with your application and should be skipped
#
#  ORDER: Arranged lowest-risk to highest-risk for application compatibility.
#         The AES and SHA384 lines are almost certain to be safe.
#         The DH key size and cipher order lines carry slightly more risk
#         with older or non-standard TLS stacks.
#
#  NOTE: All SCHANNEL changes require a reboot to take effect.
###############################################################################


# ── LINE 1 ───────────────────────────────────────────────────────────────────
# Enable SHA384 hash (completes the SHA-2 family alongside SHA256/SHA512)
# Risk: Very Low — purely additive, enables an algorithm, disables nothing
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Name "Enabled" -Value 1 -Type DWord


# ── LINE 2 ───────────────────────────────────────────────────────────────────
# Explicitly enable AES 128/128 cipher
# Risk: Very Low — purely additive, guarantees AES is available after weak ciphers are removed
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled" -Value 1 -Type DWord


# ── LINE 3 ───────────────────────────────────────────────────────────────────
# Explicitly enable AES 256/256 cipher
# Risk: Very Low — purely additive, guarantees AES 256 is available
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -Value 1 -Type DWord


# ── LINE 4 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for SSL 2.0 Server (belt-and-suspenders alongside Enabled=0)
# Risk: Very Low — belt-and-suspenders for an already-disabled protocol
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 5 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for SSL 2.0 Client
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 6 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for SSL 3.0 Server
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 7 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for SSL 3.0 Client
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 8 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for TLS 1.0 Server
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 9 ───────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for TLS 1.0 Client
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 10 ──────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for TLS 1.1 Server
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 11 ──────────────────────────────────────────────────────────────────
# Add DisabledByDefault=1 for TLS 1.1 Client
# Risk: Very Low
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1 -Type DWord


# ── LINE 12 ──────────────────────────────────────────────────────────────────
# Confirm TLS 1.2 is NOT flagged as disabled-by-default (safety check)
# Risk: None — ensures TLS 1.2 is fully and unambiguously enabled
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord


# ── LINE 13 ──────────────────────────────────────────────────────────────────
# Enable TLS 1.3 Server (Windows 10 1903+ / Server 2022 only; ignored on older OS)
# Risk: Low — ignored on unsupported OS versions; may expose incompatibilities
#       with very old TLS stacks that incorrectly handle TLS 1.3 negotiation
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1 -Type DWord; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "DisabledByDefault" -Value 0 -Type DWord


# ── LINE 14 ──────────────────────────────────────────────────────────────────
# Enable TLS 1.3 Client
# Risk: Low — same as Line 13; test outbound connections from your application
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled" -Value 1 -Type DWord; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "DisabledByDefault" -Value 0 -Type DWord


# ── LINE 15 ──────────────────────────────────────────────────────────────────
# Disable RC2 128/128 cipher
# Risk: Low-Medium — RC2 is legacy but may still be used by very old embedded
#       components or custom crypto libraries. Test any legacy integrations.
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled" -Value 0 -Type DWord


# ── LINE 16 ──────────────────────────────────────────────────────────────────
# Disable RC2 56/128 cipher
# Risk: Low-Medium — same notes as Line 15
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled" -Value 0 -Type DWord


# ── LINE 17 ──────────────────────────────────────────────────────────────────
# Disable RC2 40/128 cipher
# Risk: Low-Medium — same notes as Line 15
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled" -Value 0 -Type DWord


# ── LINE 18 ──────────────────────────────────────────────────────────────────
# Set minimum Diffie-Hellman server key size to 2048-bit (prevents Logjam attack)
# Risk: Medium — any server or peer that only supports 512/1024-bit DH will
#       fail to negotiate. Test all outbound TLS connections your app makes.
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 2048 -Type DWord


# ── LINE 19 ──────────────────────────────────────────────────────────────────
# Set minimum Diffie-Hellman client key size to 2048-bit
# Risk: Medium — same as Line 18; affects outbound connections specifically
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ClientMinKeyBitLength" -Value 2048 -Type DWord


# ── LINE 20 ──────────────────────────────────────────────────────────────────
# Enforce strong cipher suite order via Local Group Policy registry key.
# Equivalent to: gpedit.msc > Computer Config > Admin Templates > Network
#                > SSL Configuration Settings > SSL Cipher Suite Order
# Risk: Medium — if your application or a dependency hard-codes a cipher not
#       in this list, negotiation will fail. Review app TLS requirements first.
#       To revert: Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" -Type String
