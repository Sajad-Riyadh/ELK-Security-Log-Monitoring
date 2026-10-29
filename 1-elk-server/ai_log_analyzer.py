#!/usr/bin/env python3
"""
ai_log_analyzer.py - External Zero-Dependency AI SOC Log Analyzer (Elastic Basic License)

Queries security logs from Elasticsearch (security-logs-*), analyzes authentication
patterns using an LLM (Google Gemini API or local Ollama), and indexes a structured
threat report back into Elasticsearch under 'security-logs-ai-analysis'.

Compatible 100% with the free Elastic Basic license (no Enterprise/Commercial license required).

Supported AI Backends:
1. Google Gemini API: Set GEMINI_API_KEY (optional GEMINI_MODEL, default: gemini-2.5-flash)
2. Local Ollama: Set OLLAMA_HOST (e.g. http://localhost:11434, optional OLLAMA_MODEL, default: llama3.2)

Usage:
  python3 ai_log_analyzer.py [ES_HOST] [ES_USER] [ES_PASS]
"""

import os
import sys
import json
import base64
import datetime
import urllib.request
import urllib.error

# Ensure UTF-8 console output across all platforms
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def get_ai_backend():
    """Detects and returns configured AI backend settings."""
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    ollama_host = os.environ.get("OLLAMA_HOST", "").strip()

    if gemini_key:
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip()
        return "gemini", model, gemini_key
    elif ollama_host:
        model = os.environ.get("OLLAMA_MODEL", "llama3.2").strip()
        return "ollama", model, ollama_host.rstrip("/")
    else:
        print("[-] Error: No AI backend configured.", file=sys.stderr)
        print("    Please set either:", file=sys.stderr)
        print("      export GEMINI_API_KEY='your-gemini-api-key' (optional: export GEMINI_MODEL='gemini-2.5-flash')", file=sys.stderr)
        print("    OR:", file=sys.stderr)
        print("      export OLLAMA_HOST='http://localhost:11434' (optional: export OLLAMA_MODEL='llama3.2')", file=sys.stderr)
        sys.exit(1)


def fetch_security_logs(es_host, auth_header, lookback):
    """Fetches recent authentication and security logs from Elasticsearch."""
    url = f"{es_host.rstrip('/')}/security-logs-*/_search"
    query_body = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": lookback,
                                "lte": "now"
                            }
                        }
                    }
                ],
                "must_not": [
                    {"term": {"event_type.keyword": "ai_security_analysis"}},
                    {"term": {"event_type": "ai_security_analysis"}}
                ],
                "should": [
                    {"match": {"message": "Failed password"}},
                    {"match": {"message": "Accepted password"}},
                    {"term": {"event_type.keyword": "ssh_failed_login"}},
                    {"term": {"event_type.keyword": "ssh_successful_login"}},
                    {"term": {"event_type.keyword": "windows_failed_login"}},
                    {"term": {"event_type.keyword": "windows_successful_login"}},
                    {"term": {"winlog.event_id": 4625}},
                    {"term": {"winlog.event_id": "4625"}},
                    {"term": {"winlog.event_id": 4624}},
                    {"term": {"winlog.event_id": "4624"}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(query_body).encode("utf-8"),
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read().decode("utf-8"))
            return data.get("hits", {}).get("hits", [])
    except urllib.error.HTTPError as e:
        print(f"[-] Elasticsearch HTTP Error ({e.code}): {e.read().decode('utf-8')}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Could not connect to Elasticsearch at {es_host}: {e}", file=sys.stderr)
        sys.exit(1)


def simplify_logs(hits):
    """Reduces raw log documents to the essential fields needed for AI analysis."""
    simplified = []
    for hit in hits:
        src = hit.get("_source", {})
        winlog = src.get("winlog") if isinstance(src.get("winlog"), dict) else {}
        winlog_event_data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
        host = src.get("host")
        host_name = host.get("name") if isinstance(host, dict) else host

        entry = {
            "timestamp": src.get("@timestamp"),
            "event_type": src.get("event_type"),
            "host": host_name,
            "ssh_user": src.get("ssh_user"),
            "src_ip": src.get("src_ip"),
            "winlog_event_id": winlog.get("event_id"),
            "winlog_user": winlog_event_data.get("TargetUserName"),
            "message": src.get("message")
        }
        simplified.append(entry)
    return simplified


def call_gemini(prompt, api_key, model):
    """Invokes Google Gemini API with responseMimeType='application/json'."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.2
        }
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            text = res_data["candidates"][0]["content"]["parts"][0]["text"]
            return parse_json_response(text)
    except urllib.error.HTTPError as e:
        print(f"[-] Gemini API Error ({e.code}): {e.read().decode('utf-8')}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Gemini API request failed: {e}", file=sys.stderr)
        sys.exit(1)


def call_ollama(prompt, host, model):
    """Invokes local Ollama API with format='json'."""
    url = f"{host}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            text = res_data.get("response", "{}")
            return parse_json_response(text)
    except urllib.error.HTTPError as e:
        print(f"[-] Ollama API Error ({e.code}): {e.read().decode('utf-8')}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Ollama request failed at {host}: {e}", file=sys.stderr)
        sys.exit(1)


def parse_json_response(text):
    """Safely parses LLM text response into a dictionary, stripping markdown if present."""
    clean = text.strip()
    if clean.startswith("```json"):
        clean = clean[7:]
    elif clean.startswith("```"):
        clean = clean[3:]
    if clean.endswith("```"):
        clean = clean[:-3]
    clean = clean.strip()
    return json.loads(clean)


def analyze_logs(backend_type, model, credential, logs):
    """Prompts the LLM as a Senior SOC Analyst and returns the structured report."""
    prompt = f"""You are a Senior Security Operations Center (SOC) Analyst analyzing security authentication logs from a hybrid Linux/Windows network.
Analyze the following batch of security telemetry ({len(logs)} events) for brute-force attacks, credential stuffing, anomalous logon spikes, or unauthorized account compromises.

Logs to analyze:
{json.dumps(logs, indent=2)}

You must return a single strict JSON object with EXACTLY the following keys:
- threat_detected: boolean (true if an attack, brute-force attempt, or anomalous authentication behavior is detected; otherwise false)
- severity: string ("CRITICAL", "HIGH", "MEDIUM", or "LOW")
- attack_type: string (e.g. "SSH Brute Force", "Windows RDP Brute Force", "Credential Stuffing", "None")
- mitre_technique: string (e.g. "T1110.001 - Password Guessing", "T1078 - Valid Accounts", "N/A")
- attacker_ips: list of strings (source IP addresses performing attacks)
- targeted_users: list of strings (usernames targeted or attempted)
- compromised: boolean (true if an attack was followed by a successful login indicating account compromise; otherwise false)
- summary: string (concise 2-3 sentence executive summary explaining what occurred)
- remediation: string (clear, actionable remediation steps for network and system administrators)

Return valid JSON only. Do not add conversational text or markdown code fences."""

    if backend_type == "gemini":
        return call_gemini(prompt, credential, model)
    else:
        return call_ollama(prompt, credential, model)


def index_ai_report(es_host, auth_header, report):
    """Indexes the structured AI report into 'security-logs-ai-analysis'."""
    url = f"{es_host.rstrip('/')}/security-logs-ai-analysis/_doc"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    doc = {
        "@timestamp": now_iso,
        "event_type": "ai_security_analysis",
        "host": {"name": "ai-soc-analyst"},
        "ai": report,
        "message": f"[AI SOC {report.get('severity', 'UNKNOWN')}] {report.get('attack_type', 'Security Analysis')}: {report.get('summary', '')}"
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(doc).encode("utf-8"),
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            return res.status in (200, 201)
    except Exception as e:
        print(f"[-] Warning: Failed to index AI report into Elasticsearch: {e}", file=sys.stderr)
        return False


def main():
    es_host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ES_HOST", "http://localhost:9200")
    es_user = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("ES_USER", "elastic")
    es_pass = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("ELASTIC_PASSWORD", "Admin123!@#")
    lookback = os.environ.get("AI_LOOKBACK", "now-30m")

    auth_str = f"{es_user}:{es_pass}"
    auth_header = "Basic " + base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

    backend_type, model, credential = get_ai_backend()

    print("============================================================")
    print(" 🤖 AI SOC Log Analyzer (Elastic Basic License)")
    print("============================================================")
    print(f" Target Elasticsearch : {es_host}")
    print(f" AI Backend           : {backend_type.upper()} ({model})")
    print(f" Query Lookback       : {lookback}")
    print("------------------------------------------------------------")

    print(f"[*] Querying recent security logs from {es_host}/security-logs-*/_search...")
    raw_hits = fetch_security_logs(es_host, auth_header, lookback)

    if not raw_hits:
        print(f"[!] No matching security logs found in the last {lookback}. System is quiet.")
        sys.exit(0)

    print(f"[+] Found {len(raw_hits)} security events. Preparing for AI analysis...")
    simplified = simplify_logs(raw_hits)

    print(f"[*] Sending logs to {backend_type.upper()} ({model}) for threat evaluation...")
    report = analyze_logs(backend_type, model, credential, simplified)

    print("[*] Indexing structured AI threat report into Elasticsearch...")
    indexed = index_ai_report(es_host, auth_header, report)

    print("\n============================================================")
    print(" 📋 AI SOC Analyst Threat Report")
    print("============================================================")
    print(f" Threat Detected  : {report.get('threat_detected')}")
    print(f" Severity         : {report.get('severity')}")
    print(f" Attack Type      : {report.get('attack_type')}")
    print(f" MITRE Technique  : {report.get('mitre_technique')}")
    print(f" Account Compromise: {report.get('compromised')}")
    print(f" Attacker IPs     : {', '.join(report.get('attacker_ips', [])) if report.get('attacker_ips') else 'None'}")
    print(f" Targeted Users   : {', '.join(report.get('targeted_users', [])) if report.get('targeted_users') else 'None'}")
    print("------------------------------------------------------------")
    print(" Executive Summary:")
    print(f"  {report.get('summary')}")
    print("------------------------------------------------------------")
    print(" Remediation Guidance:")
    print(f"  {report.get('remediation')}")
    print("============================================================")

    if indexed:
        print("[+] Report successfully indexed to: security-logs-ai-analysis")
        print("👉 Kibana Discover Filter : event_type : \"ai_security_analysis\"")
        if report.get("severity") in ("CRITICAL", "HIGH"):
            print("🚨 Alert Triggered        : 🤖 AI Critical Threat Detected")
    else:
        print("[-] Note: Report was generated but indexing encountered an issue.")


if __name__ == "__main__":
    main()
