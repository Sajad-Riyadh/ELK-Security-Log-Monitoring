# =============================================================================
# Windows Host - Disable Remote Desktop & Cleanup (Post-Demo Teardown)
# Run this script as Administrator after completing your security demo.
#
# Actions:
#   1. Disables Remote Desktop in the Windows registry (fDenyTSConnections = 1)
#   2. Stops Remote Desktop Services (TermService) and resets startup to Manual
#   3. Closes and disables Windows Firewall rules for Remote Desktop (port 3389)
#   4. Resets RemoteAddress restrictions on the firewall rule
#   5. Deletes the temporary 'testrdp' local test account
# =============================================================================

#Requires -RunAsAdministrator
param(
    [string]$TestUser = "testrdp"
)

$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Physical Host: RDP Post-Demo Cleanup       " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# ---- 1. Disable RDP in Registry & Stop TermService ----
Write-Host "[*] Disabling Remote Desktop in registry (fDenyTSConnections = 1)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 1 -Type DWord
Write-Host "[+] Remote Desktop disabled in registry." -ForegroundColor Green

Write-Host "[*] Stopping Remote Desktop Services (TermService)..."
Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
Set-Service -Name "TermService" -StartupType Manual -ErrorAction SilentlyContinue
Write-Host "[+] TermService stopped and reverted to Manual." -ForegroundColor Green

# ---- 2. Disable & Reset Windows Firewall Rule ----
Write-Host "[*] Disabling Remote Desktop firewall rules..."
Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

$rdpRuleName = "RemoteDesktop-UserMode-In-TCP"
Set-NetFirewallRule -Name $rdpRuleName -RemoteAddress Any -Enabled False -ErrorAction SilentlyContinue
Write-Host "[+] Remote Desktop port 3389 is now closed in firewall." -ForegroundColor Green

# ---- 3. Remove Temporary Test Account ----
Write-Host "[*] Checking for temporary lab user '$TestUser'..."
if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
    # Remove from Remote Desktop Users group first
    Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $TestUser -ErrorAction SilentlyContinue
    # Delete the local user account
    Remove-LocalUser -Name $TestUser -ErrorAction Stop
    Write-Host "[+] Local test account '$TestUser' has been deleted." -ForegroundColor Green
} else {
    Write-Host "[+] User '$TestUser' not found (already removed)." -ForegroundColor Green
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Post-Demo Cleanup Complete!"                  -ForegroundColor Green
Write-Host "   - RDP has been DISABLED"                    -ForegroundColor Green
Write-Host "   - Firewall port 3389 has been CLOSED"       -ForegroundColor Green
Write-Host "   - Test account '$TestUser' has been DELETED" -ForegroundColor Green
Write-Host " Physical host is restored to its secure state." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
