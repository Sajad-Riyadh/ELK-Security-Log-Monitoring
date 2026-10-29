#!/usr/bin/env bash
# =============================================================================
# ELK Server Setup Script (Interactive Authentication)
# Prompts for admin credentials, installs Docker, tunes sysctl, generates
# unique Kibana encryption keys, starts Elasticsearch, sets kibana_system
# credentials, creates custom admin users, and brings up the monitoring stack.
#
# Usage:
#   sudo bash setup_elk.sh [ADMIN_USERNAME] [ADMIN_PASSWORD]
# =============================================================================
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (use: sudo bash setup_elk.sh)." >&2
    exit 1
fi

echo "============================================="
echo " ELK Stack - Server Setup (Lab Mode)"
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
    apt-get install -y ca-certificates curl gnupg lsb-release openssl

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

gen_key() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 16
    else
        head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

echo "[*] Writing secure .env configuration..."
cat > .env << ENVEOF
ELASTIC_PASSWORD=${ADMIN_PASSWORD}
KIBANA_PASSWORD=${ADMIN_PASSWORD}
XPACK_SECURITY_ENCRYPTIONKEY=$(gen_key)
XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=$(gen_key)
XPACK_REPORTING_ENCRYPTIONKEY=$(gen_key)
ENVEOF
chmod 600 .env

# ---- 4. Launch Elasticsearch ----
echo "[*] Starting Elasticsearch container..."
docker compose up -d elasticsearch

echo "[*] Waiting for Elasticsearch to become healthy..."
MAX_WAIT=60
COUNT=0
until curl -sf -u "elastic:${ADMIN_PASSWORD}" http://localhost:9200/_cluster/health >/dev/null; do
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -ge "$MAX_WAIT" ]; then
        echo "[-] Error: Elasticsearch did not become healthy within $((MAX_WAIT * 3)) seconds." >&2
        exit 1
    fi
    sleep 3
done
echo "[+] Elasticsearch is healthy."

# ---- 5. Set password for internal kibana_system service account ----
echo "[*] Configuring internal kibana_system credentials..."
curl -sf -X POST -u "elastic:${ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  http://localhost:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${ADMIN_PASSWORD}\"}" >/dev/null
echo "[+] kibana_system service account configured."

# ---- 6. Create custom administrator user if requested ----
if [ "$ADMIN_USER" != "elastic" ]; then
    echo "[*] Creating custom administrator account '${ADMIN_USER}'..."
    curl -sf -X POST -u "elastic:${ADMIN_PASSWORD}" \
      -H "Content-Type: application/json" \
      "http://localhost:9200/_security/user/${ADMIN_USER}" \
      -d "{\"password\":\"${ADMIN_PASSWORD}\", \"roles\":[\"superuser\"], \"full_name\":\"Security Administrator\"}" >/dev/null
    echo "[+] Custom user '${ADMIN_USER}' created with superuser privileges."
fi

# ---- 7. Launch Kibana and Logstash ----
echo "[*] Starting Kibana and Logstash..."
docker compose up -d kibana logstash

# ---- 8. Provision Observability Alert Rules (if python3 is available) ----
if command -v python3 &>/dev/null && [ -f "${SCRIPT_DIR}/setup_rules.py" ]; then
    echo "[*] Waiting for Kibana to become ready to provision alert rules..."
    for i in {1..40}; do
        if curl -sf -u "${ADMIN_USER}:${ADMIN_PASSWORD}" http://localhost:5601/api/status &>/dev/null; then
            echo "[*] Provisioning Data View and Observability Alert Rules..."
            sleep 2
            python3 "${SCRIPT_DIR}/setup_rules.py" "http://localhost:5601" "${ADMIN_USER}" "${ADMIN_PASSWORD}" || {
                echo "[!] Note: Alert rules can also be provisioned manually anytime via: python3 setup_rules.py"
            }
            break
        fi
        sleep 3
    done
fi

echo ""
echo "============================================="
echo " ELK Stack is UP and RUNNING with AUTHENTICATION!"
echo "---------------------------------------------"
echo " Kibana Dashboard : http://<SERVER_IP>:5601"
echo " Observability    : http://<SERVER_IP>:5601/app/observability/alerts"
echo " Elasticsearch    : http://<SERVER_IP>:9200"
echo " Logstash Beats   : port 5044"
echo "---------------------------------------------"
echo " Login Credentials:"
echo "   Username : ${ADMIN_USER}"
echo "   Password : (stored in 1-elk-server/.env)"
echo "============================================="
