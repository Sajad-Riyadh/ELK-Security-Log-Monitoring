# =============================================================================
# Windows Client - Winlogbeat Setup
# Downloads, configures, and installs Winlogbeat to ship Windows Event Logs
# (Security, System, Application) to the ELK Logstash instance.
#
# Usage (run as Administrator):
#   powershell -ExecutionPolicy Bypass -File setup_winlogbeat.ps1 -ElkIP <IP>
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
# =============================================================================

#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$ElkIP
)

$ErrorActionPreference = "Stop"

$WinlogbeatVersion = "8.17.0"
$InstallDir = "C:\Program Files\Winlogbeat"
$ConfigFile = "$InstallDir\winlogbeat.yml"
$ZipUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-${WinlogbeatVersion}-windows-x86_64.zip"
$ZipFile = "$env:TEMP\winlogbeat.zip"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Winlogbeat ${WinlogbeatVersion} Setup"       -ForegroundColor Cyan
Write-Host " ELK Server: ${ElkIP}"                        -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# ---- 1. Download and extract Winlogbeat ----
if (-Not (Test-Path "$InstallDir\winlogbeat.exe")) {
    Write-Host "[*] Downloading Winlogbeat ${WinlogbeatVersion}..."
    Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipFile -UseBasicParsing

    Write-Host "[*] Extracting to ${InstallDir}..."
    Expand-Archive -Path $ZipFile -DestinationPath $env:TEMP -Force
    $ExtractedDir = Get-ChildItem "$env:TEMP\winlogbeat-*" -Directory | Select-Object -First 1

    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Move-Item -Path $ExtractedDir.FullName -Destination $InstallDir
    Remove-Item $ZipFile -Force
    Write-Host "[+] Winlogbeat extracted." -ForegroundColor Green
} else {
    Write-Host "[+] Winlogbeat is already installed at ${InstallDir}." -ForegroundColor Green
}

# ---- 2. Write Winlogbeat configuration ----
Write-Host "[*] Writing winlogbeat.yml..."
$config = @"
# =============================================================================
# Winlogbeat Configuration - Security Log Monitoring
# Ships Security, System, and Application event logs to the ELK server.
# =============================================================================

winlogbeat.event_logs:
  - name: Security
    ignore_older: 24h
  - name: System
    ignore_older: 24h
  - name: Application
    ignore_older: 24h

output.logstash:
  hosts: ["${ElkIP}:5044"]

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\logs
  name: winlogbeat.log
  keepfiles: 3
"@

Set-Content -Path $ConfigFile -Value $config -Encoding UTF8
Write-Host "[+] Configuration written to ${ConfigFile}." -ForegroundColor Green

# ---- 3. Install and start the Winlogbeat service ----
Write-Host "[*] Installing Winlogbeat service..."
Push-Location $InstallDir
try {
    PowerShell.exe -ExecutionPolicy Bypass -File .\install-service-winlogbeat.ps1
} finally {
    Pop-Location
}

Write-Host "[*] Starting Winlogbeat service..."
Set-Service  -Name winlogbeat -StartupType Automatic
Restart-Service -Name winlogbeat -Force
Write-Host "[+] Winlogbeat service is running." -ForegroundColor Green

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Winlogbeat setup complete!"                   -ForegroundColor Cyan
Write-Host " Logs are being shipped to ${ElkIP}:5044"      -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
