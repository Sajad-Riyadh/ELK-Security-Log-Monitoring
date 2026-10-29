#!/usr/bin/env bash
# =============================================================================
# Linux Client Setup Script
# Installs OpenSSH & rsyslog, creates a test user, installs Filebeat 8.x, and
# configures it to ship auth.log and syslog to the ELK server via Logstash.
#
# Usage:
#   sudo bash setup_filebeat.sh <ELK_IP> [TEST_USER] [TEST_PASSWORD]
#
# Examples:
#   # Interactive prompt (prompts for custom username and password, no defaults):
#   sudo bash setup_filebeat.sh 192.168.1.10
#
#   # Direct arguments:
#   sudo bash setup_filebeat.sh 192.168.1.10 'myuser' 'MySecurePassword123!'
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
# =============================================================================
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (use: sudo bash setup_filebeat.sh <ELK_IP>)." >&2
    exit 1
fi

ELK_IP="${1:?Error: Please provide the ELK server IP as the first argument. (Example: sudo bash setup_filebeat.sh 192.168.1.10)}"
INPUT_USER="${2:-}"
INPUT_PASSWORD="${3:-}"

# Handle Test Username (No default)
if [ -n "$INPUT_USER" ]; then
    TEST_USER="$INPUT_USER"
elif [ -t 0 ]; then
    while true; do
        echo -n "[?] Enter Linux Test Username: "
        read -r TEST_USER
        if [ -n "$TEST_USER" ]; then
            break
        fi
        echo "[-] Username cannot be empty. Please enter a valid username."
    done
else
    echo "[-] Error: Non-interactive execution requires arguments: sudo bash setup_filebeat.sh <ELK_IP> <TEST_USER> <TEST_PASSWORD>" >&2
    exit 1
fi

# Handle Test Password (No default)
if [ -n "$INPUT_PASSWORD" ]; then
    TEST_PASSWORD="$INPUT_PASSWORD"
elif [ -t 0 ]; then
    while true; do
        echo -n "[?] Enter password for user '${TEST_USER}' (hidden): "
        read -r -s TEST_PASSWORD
        echo ""
        if [ -z "$TEST_PASSWORD" ]; then
            echo "[-] Password cannot be empty. Please enter a password."
            continue
        fi

        echo -n "[?] Confirm password for user '${TEST_USER}' (hidden): "
        read -r -s CONFIRM_PASSWORD
        echo ""

        if [ "$TEST_PASSWORD" = "$CONFIRM_PASSWORD" ]; then
            break
        else
            echo "[!] Passwords do not match. Please try again."
        fi
    done
else
    echo "[-] Error: Non-interactive execution requires arguments: sudo bash setup_filebeat.sh <ELK_IP> <TEST_USER> <TEST_PASSWORD>" >&2
    exit 1
fi

echo "============================================="
echo " Linux Client - Filebeat Setup"
echo " ELK Server : ${ELK_IP}"
echo " User       : ${TEST_USER}"
echo "============================================="

# ---- 1. Install and configure OpenSSH Server & rsyslog ----
echo "[*] Installing openssh-server and rsyslog..."
apt-get update -y
apt-get install -y openssh-server rsyslog wget gpg

systemctl enable --now rsyslog

echo "[*] Enabling PasswordAuthentication in ssh configuration..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
mkdir -p /etc/ssh/sshd_config.d
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/60-password-auth.conf

# Restart SSH service (Ubuntu/Debian uses 'ssh', CentOS/RHEL uses 'sshd')
if systemctl list-unit-files | grep -q "^ssh\.service"; then
    systemctl restart ssh
elif systemctl list-unit-files | grep -q "^sshd\.service"; then
    systemctl restart sshd
else
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
fi

# On modern Ubuntu (24.04+), socket activation is also used
systemctl restart ssh.socket 2>/dev/null || true
echo "[+] SSH server configured."

# ---- 2. Create test user ----
if id "${TEST_USER}" &>/dev/null; then
    echo "[+] User '${TEST_USER}' already exists. Updating password..."
    chpasswd <<< "${TEST_USER}:${TEST_PASSWORD}"
else
    echo "[*] Creating user '${TEST_USER}'..."
    useradd -m -s /bin/bash "${TEST_USER}"
    chpasswd <<< "${TEST_USER}:${TEST_PASSWORD}"
    echo "[+] User '${TEST_USER}' created."
fi

# ---- 3. Install Filebeat 8.x ----
if ! command -v filebeat &>/dev/null; then
    echo "[*] Installing Filebeat 8.x..."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
        gpg --dearmor --yes -o /usr/share/keyrings/elastic-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main" | \
        tee /etc/apt/sources.list.d/elastic-8.x.list > /dev/null
    apt-get update -y
    apt-get install -y filebeat
    echo "[+] Filebeat installed."
else
    echo "[+] Filebeat is already installed."
fi

# ---- 4. Write Filebeat configuration ----
echo "[*] Writing /etc/filebeat/filebeat.yml..."
cat > /etc/filebeat/filebeat.yml << FBEOF
# =============================================================================
# Filebeat Configuration - Security Log Monitoring
# Ships auth.log and syslog to the ELK Logstash instance.
# =============================================================================

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
    fields:
      source_type: linux_security
    fields_under_root: true

output.logstash:
  hosts: ["${ELK_IP}:5044"]

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat.log
  keepfiles: 3
FBEOF

chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml
echo "[+] Filebeat configuration written (permissions: 600)."

# ---- 5. Enable and start Filebeat ----
echo "[*] Starting Filebeat service..."
systemctl enable filebeat
systemctl restart filebeat
echo "[+] Filebeat is running."

echo ""
echo "============================================="
echo " Linux client setup complete!"
echo " Logs are being shipped to ${ELK_IP}:5044"
echo "============================================="
