#!/usr/bin/env bash
# =============================================================================
# ELK Server Setup Script (Interactive Authentication)
# Prompts for admin credentials, installs Docker, tunes sysctl, starts
# Elasticsearch, sets kibana_system credentials, creates custom admin users,
# and brings up the complete monitoring stack.
#
# Usage:
#   sudo bash setup_elk.sh [ADMIN_USERNAME] [ADMIN_PASSWORD]
# =============================================================================
set -euo pipefail

echo "============================================="
echo " ELK Stack - Server Setup (Production Mode)"
echo "============================================="

# ---- 0. Prompt for Username and Password ----
INPUT_USER="${1:-}"
INPUT_PASS="${2:-}"

# Handle Admin Username
if [ -n "$INPUT_USER" ]; then
    ADMIN_USER="$INPUT_USER"
elif [ -t 0 ]; then
    echo -n "[?] Enter Admin Username [default: elastic]: "
    read -r ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-elastic}"
else
    ADMIN_USER="${ELASTIC_USER:-elastic}"
fi

# Handle Admin Password
if [ -n "$INPUT_PASS" ]; then
    ADMIN_PASSWORD="$INPUT_PASS"
elif [ -t 0 ]; then
    while true; do
        echo -n "[?] Enter Admin Password (hidden) [default: Admin123!@#]: "
        read -r -s ADMIN_PASSWORD
        echo ""
        ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin123!@#}"

        # If user selected default, no need for confirmation
        if [ "$ADMIN_PASSWORD" = "Admin123!@#" ]; then
            break
        fi

        echo -n "[?] Confirm Admin Password (hidden): "
        read -r -s CONFIRM_PASSWORD
        echo ""

        if [ "$ADMIN_PASSWORD" = "$CONFIRM_PASSWORD" ]; then
            break
        else
            echo "[!] Passwords do not match. Please try again."
        fi
    done
else
    ADMIN_PASSWORD="${ELASTIC_PASSWORD:-Admin123!@#}"
fi

echo "[+] Using administrator username: '${ADMIN_USER}'"

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

# ---- 3. Write .env file for Docker Compose ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Writing secure .env configuration..."
cat > .env << ENVEOF
ELASTIC_PASSWORD=${ADMIN_PASSWORD}
KIBANA_PASSWORD=${ADMIN_PASSWORD}
ENVEOF
chmod 600 .env

# ---- 4. Launch Elasticsearch ----
echo "[*] Starting Elasticsearch container..."
sudo docker compose up -d elasticsearch

echo "[*] Waiting for Elasticsearch to become healthy..."
until curl -sf -u "elastic:${ADMIN_PASSWORD}" http://localhost:9200/_cluster/health >/dev/null; do
    sleep 3
done
echo "[+] Elasticsearch is healthy."

# ---- 5. Set password for internal kibana_system service account ----
echo "[*] Configuring internal kibana_system credentials..."
curl -s -X POST -u "elastic:${ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  http://localhost:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${ADMIN_PASSWORD}\"}" >/dev/null
echo "[+] kibana_system service account configured."

# ---- 6. Create custom administrator user if requested ----
if [ "$ADMIN_USER" != "elastic" ]; then
    echo "[*] Creating custom administrator account '${ADMIN_USER}'..."
    curl -s -X POST -u "elastic:${ADMIN_PASSWORD}" \
      -H "Content-Type: application/json" \
      "http://localhost:9200/_security/user/${ADMIN_USER}" \
      -d "{\"password\":\"${ADMIN_PASSWORD}\", \"roles\":[\"superuser\"], \"full_name\":\"Security Administrator\"}" >/dev/null
    echo "[+] Custom user '${ADMIN_USER}' created with superuser privileges."
fi

# ---- 7. Launch Kibana and Logstash ----
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
echo "   Username : ${ADMIN_USER}"
echo "   Password : (configured securely)"
echo "============================================="
