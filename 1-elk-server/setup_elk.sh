#!/usr/bin/env bash
# =============================================================================
# ELK Server Setup Script (with Authentication Enabled)
# Installs Docker, tunes sysctl, starts Elasticsearch, configures Kibana
# authentication, and brings up the full monitoring stack.
# Run as root or with sudo on Ubuntu/Debian.
# =============================================================================
set -euo pipefail

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-Admin123!@#}"

echo "============================================="
echo " ELK Stack - Server Setup (Production Mode)"
echo "============================================="

# ---- 1. Install Docker (official method) ----
if ! command -v docker &>/dev/null; then
    echo "[*] Installing Docker..."
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
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

# ---- 3. Launch Elasticsearch ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Starting Elasticsearch container..."
sudo docker compose up -d elasticsearch

echo "[*] Waiting for Elasticsearch to become healthy..."
until curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cluster/health >/dev/null; do
    sleep 3
done
echo "[+] Elasticsearch is healthy."

# ---- 4. Set password for internal kibana_system service account ----
echo "[*] Configuring internal kibana_system credentials..."
curl -s -X POST -u "elastic:${ELASTIC_PASSWORD}" \
  -H "Content-Type: application/json" \
  http://localhost:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${ELASTIC_PASSWORD}\"}" >/dev/null
echo "[+] kibana_system service account configured."

# ---- 5. Launch Kibana and Logstash ----
echo "[*] Starting Kibana and Logstash..."
sudo docker compose up -d kibana logstash

echo ""
echo "============================================="
echo " ELK Stack is UP and RUNNING with AUTHENTICATION!"
echo "---------------------------------------------"
echo " Kibana Dashboard : http://<SERVER_IP>:5601"
echo " Elasticsearch    : http://<SERVER_IP>:9200"
echo " Logstash Beats   : port 5044"
echo "---------------------------------------------"
echo " Login Credentials:"
echo "   Username : elastic"
echo "   Password : ${ELASTIC_PASSWORD}"
echo "============================================="
