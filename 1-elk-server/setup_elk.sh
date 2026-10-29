#!/usr/bin/env bash
# =============================================================================
# ELK Server Setup Script
# Installs Docker, tunes the kernel for Elasticsearch, and launches the stack.
# Run as root or with sudo on Ubuntu/Debian.
# =============================================================================
set -euo pipefail

echo "============================================="
echo " ELK Stack - Server Setup"
echo "============================================="

# ---- 1. Install Docker (official method) ----
if ! command -v docker &>/dev/null; then
    echo "[*] Installing Docker..."
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    echo "[+] Docker installed successfully."
else
    echo "[+] Docker is already installed."
fi

# ---- 2. Set vm.max_map_count (required by Elasticsearch) ----
echo "[*] Setting vm.max_map_count=262144..."
sysctl -w vm.max_map_count=262144

if grep -q "^vm.max_map_count" /etc/sysctl.conf; then
    sed -i 's/^vm.max_map_count.*/vm.max_map_count=262144/' /etc/sysctl.conf
else
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
fi
echo "[+] vm.max_map_count persisted in /etc/sysctl.conf."

# ---- 3. Launch the ELK stack ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[*] Starting ELK stack from ${SCRIPT_DIR}..."
cd "$SCRIPT_DIR"
sudo docker compose up -d

echo ""
echo "============================================="
echo " ELK Stack is starting up!"
echo " Elasticsearch : http://<SERVER_IP>:9200"
echo " Kibana        : http://<SERVER_IP>:5601"
echo " Logstash Beats: port 5044"
echo "============================================="
