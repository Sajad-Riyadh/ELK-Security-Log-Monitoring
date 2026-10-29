#!/usr/bin/env python3
"""
setup_rules.py - Automatic Observability Alert Rules Provisioner for Kibana 8.x

Configures the 3 core security alert rules inside Kibana Observability:
  1. 🚨 SSH Brute Force Detection (Threshold > 3 failed logins in 5m)
  2. 🚨 Windows RDP Brute Force Detection (Threshold > 3 failed RDP logins in 5m)
  3. 🟢 Successful Login After Attack (Threshold > 0 accepted logins in 5m)

Evaluation Schedule: Every 10 seconds (for rapid lab & SOC demonstration).
"""

import sys
import json
import base64
import urllib.request
import urllib.error

def main():
    kibana_host = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5601"
    admin_user = sys.argv[2] if len(sys.argv) > 2 else "elastic"
    admin_pass = sys.argv[3] if len(sys.argv) > 3 else "Admin123!@#"

    auth_header = "Basic " + base64.b64encode(f"{admin_user}:{admin_pass}".encode()).decode()
    headers = {
        "Authorization": auth_header,
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }

    print("=============================================")
    print(" Kibana Observability Alert Rules Setup")
    print(f" Target Kibana: {kibana_host}")
    print("=============================================")

    # 1. Lookup 'Security Logs' Data View ID
    dv_id = "d7cad565-0b39-4463-997e-630cc18b17e3"
    try:
        req = urllib.request.Request(f"{kibana_host}/api/data_views", headers=headers)
        res = urllib.request.urlopen(req)
        dvs = json.loads(res.read()).get("data_view", [])
        for dv in dvs:
            if "security-logs" in dv.get("title", ""):
                dv_id = dv.get("id", dv_id)
                break
    except Exception as e:
        print(f"[*] Using default Data View ID ({dv_id})")

    rules_to_create = [
        {
            "name": "🚨 SSH Brute Force Detection",
            "tags": ["security", "ssh", "bruteforce"],
            "query": 'message : "Failed password" or event_type : "ssh_failed_login"',
            "threshold": 3,
            "window": 5
        },
        {
            "name": "🚨 Windows RDP Brute Force Detection",
            "tags": ["security", "rdp", "windows"],
            "query": 'winlog.event_id : "4625" or event_type : "windows_failed_login"',
            "threshold": 3,
            "window": 5
        },
        {
            "name": "🟢 Successful Login After Attack",
            "tags": ["security", "audit", "success"],
            "query": 'message : "Accepted password" or winlog.event_id : "4624"',
            "threshold": 0,
            "window": 5
        }
    ]

    # Find existing rules to update or avoid duplicates
    existing_rules = {}
    try:
        find_req = urllib.request.Request(f"{kibana_host}/api/alerting/rules/_find?per_page=100", headers=headers)
        find_res = urllib.request.urlopen(find_req)
        for r in json.loads(find_res.read()).get("data", []):
            existing_rules[r.get("name")] = r.get("id")
    except Exception as e:
        print(f"[-] Could not query existing rules: {e}")

    for r_def in rules_to_create:
        payload = {
            "name": r_def["name"],
            "tags": r_def["tags"],
            "rule_type_id": ".es-query",
            "consumer": "logs",
            "schedule": {"interval": "10s"},
            "actions": [],
            "params": {
                "searchConfiguration": {
                    "query": {
                        "query": r_def["query"],
                        "language": "kuery"
                    },
                    "index": dv_id
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
                "sourceFields": [{"label": "host.name", "searchPath": "host.name.keyword"}]
            }
        }

        if r_def["name"] in existing_rules:
            rule_id = existing_rules[r_def["name"]]
            print(f"[*] Updating existing rule: {r_def['name']} ({rule_id})...")
            req = urllib.request.Request(
                f"{kibana_host}/api/alerting/rule/{rule_id}",
                data=json.dumps(payload).encode(),
                headers=headers,
                method="PUT"
            )
        else:
            print(f"[*] Creating rule: {r_def['name']}...")
            req = urllib.request.Request(
                f"{kibana_host}/api/alerting/rule",
                data=json.dumps(payload).encode(),
                headers=headers,
                method="POST"
            )

        try:
            res = urllib.request.urlopen(req)
            print(f"[+] Successfully saved {r_def['name']} (HTTP {res.status})")
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP error {e.code}: {e.read().decode()}")
        except Exception as e:
            print(f"[-] Error: {e}")

    print("\n[+] All Observability Alert Rules are active and evaluating every 10 seconds.")
    print(f"👉 Check Observability Alerts at: {kibana_host}/app/observability/alerts")

if __name__ == "__main__":
    main()
