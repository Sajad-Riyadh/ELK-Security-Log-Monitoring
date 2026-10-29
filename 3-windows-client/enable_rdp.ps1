# =============================================================================
# Windows Client - Enable Remote Desktop
# Run this script as Administrator.
#
# Usage:
#   .\enable_rdp.ps1 [-TestPassword <password>]
#
# Parameters:
#   TestPassword - Password for the local 'testuser' account used by the
#                  Kali RDP brute-force phase (default: "ChangeMe_LabOnly").
#                  Use the SAME value you pass to attack_simulation.sh so the
#                  brute-force run ends in a successful login.
#
# NOTE: Remote Desktop (host/server side) requires Windows 11 Pro,
#       Enterprise, or Education. Windows 11 Home cannot accept
#       incoming RDP connections.
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
#          Do NOT enable RDP on internet-facing or production systems
#          without proper hardening (NLA, firewall rules, VPN, etc.).
# =============================================================================

#Requires -RunAsAdministrator
param(
    [string]$TestPassword = "ChangeMe_LabOnly"
)

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Enabling Remote Desktop (RDP)"               -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# ---- 1. Enable RDP via Registry ----
Write-Host "[*] Setting fDenyTSConnections = 0 ..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0 -Type DWord
Write-Host "[+] Remote Desktop enabled in registry." -ForegroundColor Green

# ---- 2. Open Firewall for RDP (port 3389) ----
Write-Host "[*] Configuring firewall rule for RDP ..."
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "[+] Firewall rule for Remote Desktop enabled." -ForegroundColor Green

# ---- 3. Create local 'testuser' account for RDP credential testing ----
# attack_simulation.sh brute-forces the account "testuser" over RDP, so it
# must exist locally and be allowed to log on via Remote Desktop.
Write-Host "[*] Creating local 'testuser' account for RDP testing..."
$SecurePassword = ConvertTo-SecureString $TestPassword -AsPlainText -Force

if (Get-LocalUser -Name "testuser" -ErrorAction SilentlyContinue) {
    Write-Host "[+] User 'testuser' already exists. Updating password..."
    Set-LocalUser -Name "testuser" -Password $SecurePassword
} else {
    Write-Host "[*] Creating user 'testuser'..."
    New-LocalUser -Name "testuser" -Password $SecurePassword `
        -PasswordNeverExpires -AccountNeverExpires -Description "Lab account for RDP log monitoring" | Out-Null
    Write-Host "[+] User 'testuser' created."
}

try {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "testuser" -ErrorAction Stop
    Write-Host "[+] 'testuser' added to the Remote Desktop Users group." -ForegroundColor Green
} catch {
    Write-Host "[+] 'testuser' is already a member of Remote Desktop Users." -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " RDP is now enabled on port 3389."            -ForegroundColor Cyan
Write-Host " Login: testuser / (password you provided)"    -ForegroundColor Cyan
Write-Host " Ensure Network Level Authentication (NLA)"   -ForegroundColor Yellow
Write-Host " is configured for production environments."  -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
