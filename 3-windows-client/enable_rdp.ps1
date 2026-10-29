# =============================================================================
# Windows Client - Enable Remote Desktop
# Run this script as Administrator.
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
#          Do NOT enable RDP on internet-facing or production systems
#          without proper hardening (NLA, firewall rules, VPN, etc.).
# =============================================================================

#Requires -RunAsAdministrator

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

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " RDP is now enabled on port 3389."            -ForegroundColor Cyan
Write-Host " Ensure Network Level Authentication (NLA)"   -ForegroundColor Yellow
Write-Host " is configured for production environments."  -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
