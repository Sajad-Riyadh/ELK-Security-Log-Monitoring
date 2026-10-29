#!/usr/bin/env python3
"""
setup_rules.py - Automatic Data View & Observability Alert Rules Provisioner for Kibana 8.x

1. Ensures the 'security-logs-*' Data View exists in Kibana (creates it if missing).
2. Configures the 3 core security alert rules inside Kibana Observability:
   - 🚨 SSH Brute Force Detection (Threshold > 3 failed logins in 5m)
   - 🚨 Windows RDP Brute Force Detection (Threshold > 3 failed RDP logins in 5m)
   - 🟢 Successful Login After Attack (Threshold > 0 accepted logins in 5m)

Evaluation Schedule: Every 10 seconds (for rapid lab & SOC demonstration).
"""

import sys
import json
import base64
import getpass
import urllib.request
import urllib.error

# Ensure UTF-8 output encoding across all operating systems / terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def main():
    if len(sys.argv) > 3:
        kibana_host = sys.argv[1]
        admin_user = sys.argv[2]
        admin_pass = sys.argv[3]
    elif sys.stdin.isatty():
        kibana_host = sys.argv[1] if len(sys.argv) > 1 else input("Enter Kibana URL [http://localhost:5601]: ").strip()
        if not kibana_host:
            kibana_host = "http://localhost:5601"
        admin_user = sys.argv[2] if len(sys.argv) > 2 else ""
        while not admin_user:
            admin_user = input("Enter Admin Username: ").strip()
        admin_pass = ""
        while not admin_pass:
            admin_pass = getpass.getpass("Enter Admin Password: ")
    else:
        print("[-] Error: Usage: python3 setup_rules.py <kibana_url> <admin_username> <admin_password>", file=sys.stderr)
        sys.exit(1)

    auth_header = "Basic " + base64.b64encode(f"{admin_user}:{admin_pass}".encode()).decode()
    headers = {
        "Authorization": auth_header,
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }

    print("=============================================")
    print(" Kibana Data View & Alert Rules Setup")
    print(f" Target Kibana: {kibana_host}")
    print("=============================================")

    # 1. Lookup or create 'security-logs-*' Data View
    dv_id = "security-logs-dataview"
    found_dv = False
    try:
        req = urllib.request.Request(f"{kibana_host}/api/data_views", headers=headers)
        res = urllib.request.urlopen(req)
        dvs = json.loads(res.read()).get("data_view", [])
        for dv in dvs:
            if "security-logs" in dv.get("title", ""):
                dv_id = dv.get("id", dv_id)
                found_dv = True
                print(f"[+] Found existing Data View 'security-logs-*' (ID: {dv_id})")
                break
    except Exception as e:
        print(f"[-] Warning: Could not list existing Data Views: {e}")

    if not found_dv:
        print("[*] Creating 'security-logs-*' Data View in Kibana...")
        dv_payload = {
            "data_view": {
                "id": dv_id,
                "title": "security-logs-*",
                "name": "Security Logs",
                "timeFieldName": "@timestamp",
            },
            "override": True,
        }
        try:
            create_req = urllib.request.Request(
                f"{kibana_host}/api/data_views/data_view",
                data=json.dumps(dv_payload).encode(),
                headers=headers,
                method="POST",
            )
            create_res = urllib.request.urlopen(create_req)
            created_dv = json.loads(create_res.read()).get("data_view", {})
            dv_id = created_dv.get("id", dv_id)
            print(f"[+] Created Data View 'security-logs-*' (ID: {dv_id})")
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP error creating Data View ({e.code}): {e.read().decode()}")
        except Exception as e:
            print(f"[-] Error creating Data View: {e}")

    rules_to_create = [
        {
            "name": "🚨 SSH Brute Force Detection",
            "tags": ["security", "ssh", "bruteforce"],
            "query": 'message : "Failed password" or event_type : "ssh_failed_login"',
            "threshold": 3,
            "window": 5,
        },
        {
            "name": "🚨 Windows RDP Brute Force Detection",
            "tags": ["security", "rdp", "windows"],
            "query": 'winlog.event_id : "4625" or event_type : "windows_failed_login"',
            "threshold": 3,
            "window": 5,
        },
        {
            "name": "🟢 Successful Login After Attack",
            "tags": ["security", "audit", "success"],
            "query": (
                'message : "Accepted password" or event_type : "ssh_successful_login" '
                'or winlog.event_id : "4624" or event_type : "windows_successful_login"'
            ),
            "threshold": 0,
            "window": 5,
        },
    ]

    # Find existing rules to update or avoid duplicates
    existing_rules = {}
    try:
        find_req = urllib.request.Request(
            f"{kibana_host}/api/alerting/rules/_find?per_page=100", headers=headers
        )
        find_res = urllib.request.urlopen(find_req)
        for r in json.loads(find_res.read()).get("data", []):
            existing_rules[r.get("name")] = r.get("id")
    except Exception as e:
        print(f"[-] Could not query existing rules: {e}")

    for r_def in rules_to_create:
        base_params = {
            "searchConfiguration": {
                "query": {
                    "query": r_def["query"],
                    "language": "kuery",
                },
                "index": dv_id,
            },
            "timeField": "@timestamp",
            "searchType": "searchSource",
            "timeWindowSize": r_def["window"],
            "timeWindowUnit": "m",
            "threshold": [r_def["threshold"]],
            "thresholdComparator": ">",
            "size": 100,
            "aggType": "count",
            "groupBy": "all",
            "termSize": 5,
            "excludeHitsFromPreviousRun": False,
            "sourceFields": [{"label": "host.name", "searchPath": "host.name.keyword"}],
        }

        if r_def["name"] in existing_rules:
            rule_id = existing_rules[r_def["name"]]
            print(f"[*] Updating existing rule: {r_def['name']} ({rule_id})...")
            update_payload = {
                "name": r_def["name"],
                "tags": r_def["tags"],
                "schedule": {"interval": "10s"},
                "actions": [],
                "params": base_params,
            }
            req = urllib.request.Request(
                f"{kibana_host}/api/alerting/rule/{rule_id}",
                data=json.dumps(update_payload).encode(),
                headers=headers,
                method="PUT",
            )
        else:
            print(f"[*] Creating rule: {r_def['name']}...")
            create_payload = {
                "name": r_def["name"],
                "tags": r_def["tags"],
                "rule_type_id": ".es-query",
                "consumer": "logs",
                "schedule": {"interval": "10s"},
                "actions": [],
                "params": base_params,
            }
            req = urllib.request.Request(
                f"{kibana_host}/api/alerting/rule",
                data=json.dumps(create_payload).encode(),
                headers=headers,
                method="POST",
            )

        try:
            res = urllib.request.urlopen(req)
            print(f"[+] Successfully saved {r_def['name']} (HTTP {res.status})")
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP error {e.code}: {e.read().decode()}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

    print("\n[+] All Observability Alert Rules are active and evaluating every 10 seconds.")
    print(f"👉 Check Observability Alerts at: {kibana_host}/app/observability/alerts")

    # Automatically provision / update the professional SOC Dashboard
    try:
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import setup_dashboard
        setup_dashboard.deploy_dashboard(kibana_host, admin_user, admin_pass)
    except Exception as e:
        print(f"[-] Note: Dashboard can also be deployed via setup_dashboard.py: {e}")


if __name__ == "__main__":
    main()
