# =============================================================================
# Windows Host - Enable Remote Desktop (Restricted Lab Account)
# Run this script as Administrator.
#
# NOTE: The Windows machine is the PHYSICAL HOST running the hypervisor / VMs.
#       For security, this script creates a dedicated, unprivileged test
#       account ('testrdp') restricted to Remote Desktop only, starts the
#       Remote Desktop Services (TermService) daemon, and allows scoping the
#       Windows Firewall rule strictly to the Kali VM IP address.
#
# Usage (PowerShell as Administrator):
#   .\enable_rdp.ps1 [-TestUser <username>] [-TestPassword <password>] [-KaliIP <IP>]
#
# Examples:
#   # Interactive prompt (prompts for custom username and password, no defaults):
#   .\enable_rdp.ps1 -KaliIP "192.168.1.13"
#
#   # Direct arguments:
#   .\enable_rdp.ps1 -TestUser "myrdpuser" -TestPassword "YourPassword123!" -KaliIP "192.168.1.13"
#
# Teardown / Cleanup:
#   When your demo is finished, run .\disable_rdp.ps1 to disable RDP,
#   stop TermService, close the firewall rule, and delete the test account.
# =============================================================================

#Requires -RunAsAdministrator
param(
    [string]$TestUser = "",
    [string]$TestPassword = "",
    [string]$KaliIP = ""
)

$ErrorActionPreference = "Stop"

# Handle Test Username (No default)
while ([string]::IsNullOrWhiteSpace($TestUser)) {
    $TestUser = Read-Host "[?] Enter Windows Test Username for RDP"
    if ([string]::IsNullOrWhiteSpace($TestUser)) {
        Write-Host "[-] Username cannot be empty. Please enter a valid username." -ForegroundColor Red
    }
}

# Handle Test Password (No default)
while ([string]::IsNullOrWhiteSpace($TestPassword)) {
    $TestPasswordSec = Read-Host "[?] Enter Password for '$TestUser'" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TestPasswordSec)
    $TestPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    if ([string]::IsNullOrWhiteSpace($TestPassword)) {
        Write-Host "[-] Password cannot be empty. Please enter a password." -ForegroundColor Red
        continue
    }

    $ConfirmSec = Read-Host "[?] Confirm Password for '$TestUser'" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmSec)
    $Confirm = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    if ($TestPassword -ne $Confirm) {
        Write-Host "[!] Passwords do not match. Please try again." -ForegroundColor Yellow
        $TestPassword = ""
    }
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Physical Host: Enable RDP (Security Lab)   " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# ---- 1. Enable RDP via Registry & Start TermService ----
Write-Host "[*] Setting fDenyTSConnections = 0 in registry..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0 -Type DWord
Write-Host "[+] Remote Desktop enabled in registry." -ForegroundColor Green

Write-Host "[*] Enabling and starting Remote Desktop Services (TermService)..."
Set-Service -Name "TermService" -StartupType Automatic
Start-Service -Name "TermService"
Write-Host "[+] TermService is running and listening on port 3389." -ForegroundColor Green

# ---- 2. Configure Firewall Rule (Scoped to Kali IP if provided) ----
Write-Host "[*] Configuring Windows Firewall rule for RDP (port 3389)..."
$rdpRuleName = "RemoteDesktop-UserMode-In-TCP"

if ($KaliIP -and ($KaliIP.Trim() -ne "")) {
    Write-Host "[+] Restricting RDP firewall rule strictly to Kali IP: $KaliIP" -ForegroundColor Green
    Enable-NetFirewallRule -Name $rdpRuleName -ErrorAction SilentlyContinue
    Set-NetFirewallRule -Name $rdpRuleName -RemoteAddress $KaliIP -Enabled True
    Write-Host "[+] Port 3389 is ONLY accessible from $KaliIP." -ForegroundColor Green
} else {
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "[!] WARNING: RDP firewall rule opened for all addresses on the local network." -ForegroundColor Yellow
    Write-Host "    Best Practice: Re-run with -KaliIP <IP> to restrict access strictly to Kali." -ForegroundColor Yellow
}

# ---- 3. Create dedicated, unprivileged test account ----
Write-Host "[*] Creating dedicated local test account '$TestUser'..."
$SecurePassword = ConvertTo-SecureString $TestPassword -AsPlainText -Force

if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
    Write-Host "[+] User '$TestUser' already exists. Updating password..."
    Set-LocalUser -Name $TestUser -Password $SecurePassword
} else {
    New-LocalUser -Name $TestUser -Password $SecurePassword `
        -PasswordNeverExpires -AccountNeverExpires `
        -Description "TEMPORARY lab account for RDP log monitoring demo ONLY" | Out-Null
    Write-Host "[+] Local user '$TestUser' created." -ForegroundColor Green
}

# Ensure the test user is strictly in Remote Desktop Users (NEVER Administrators)
try {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $TestUser -ErrorAction Stop
    Write-Host "[+] '$TestUser' added to 'Remote Desktop Users' group." -ForegroundColor Green
} catch {
    Write-Host "[+] '$TestUser' is already a member of 'Remote Desktop Users'." -ForegroundColor Green
}

# Verify user is NOT an administrator
$isAdmin = Get-LocalGroupMember -Group "Administrators" -Member $TestUser -ErrorAction SilentlyContinue
if ($isAdmin) {
    Remove-LocalGroupMember -Group "Administrators" -Member $TestUser -ErrorAction SilentlyContinue
    Write-Host "[!] Removed '$TestUser' from Administrators group for security." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " RDP Demo Configuration Active:"               -ForegroundColor Cyan
Write-Host "   Host         : Physical Windows Machine"      -ForegroundColor White
Write-Host "   Test Account : $TestUser (Standard User only)" -ForegroundColor White
Write-Host "   Firewall     : " -NoNewline
if ($KaliIP) {
    Write-Host "Restricted to $KaliIP ONLY" -ForegroundColor Green
} else {
    Write-Host "Open to Local Subnet (recommend -KaliIP)" -ForegroundColor Yellow
}
Write-Host "---------------------------------------------" -ForegroundColor Cyan
Write-Host " POST-DEMO ACTION: Run .\disable_rdp.ps1 when" -ForegroundColor Yellow
Write-Host " finished to close RDP and remove this user."   -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
