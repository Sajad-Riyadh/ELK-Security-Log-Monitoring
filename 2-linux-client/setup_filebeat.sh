#!/usr/bin/env bash
# =============================================================================
# Linux Client Setup Script
# Installs OpenSSH, creates a test user, installs Filebeat 8.x, and configures
# it to ship auth.log and syslog to the ELK server via Logstash.
#
# Usage:
#   sudo bash setup_filebeat.sh <ELK_IP> [TEST_PASSWORD]
#
# Examples:
#   # Interactive prompt (safest when passwords contain special chars like !):
#   sudo bash setup_filebeat.sh 192.168.1.10
#
#   # Direct argument (always wrap passwords containing ! in single quotes):
#   sudo bash setup_filebeat.sh 192.168.1.10 'Admin123!@#'
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
# =============================================================================
set -euo pipefail

ELK_IP="${1:?Error: Please provide the ELK server IP as the first argument. (Example: sudo bash setup_filebeat.sh 192.168.1.10)}"
INPUT_PASSWORD="${2:-}"

# Safely handle password input without bash history expansion issues
if [ -n "$INPUT_PASSWORD" ]; then
    TEST_PASSWORD="$INPUT_PASSWORD"
elif [ -t 0 ]; then
    echo -n "[?] Enter password for 'testuser' (hidden) [default: ChangeMe_LabOnly]: "
    read -r -s TEST_PASSWORD
    echo ""
    TEST_PASSWORD="${TEST_PASSWORD:-ChangeMe_LabOnly}"
else
    TEST_PASSWORD="ChangeMe_LabOnly"
fi

echo "============================================="
echo " Linux Client - Filebeat Setup"
echo " ELK Server : ${ELK_IP}"
echo " User       : testuser"
echo "============================================="

# ---- 1. Install and configure OpenSSH Server ----
echo "[*] Installing openssh-server..."
apt-get update -y
apt-get install -y openssh-server

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
if id "testuser" &>/dev/null; then
    echo "[+] User 'testuser' already exists. Updating password..."
    echo "testuser:${TEST_PASSWORD}" | chpasswd
else
    echo "[*] Creating user 'testuser'..."
    useradd -m -s /bin/bash testuser
    echo "testuser:${TEST_PASSWORD}" | chpasswd
    echo "[+] User 'testuser' created."
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
