#!/usr/bin/env python3
"""
setup_dashboard.py - Professional SOC Security Dashboard Provisioner for Kibana 8.x

Configures a high-impact, professional SIEM Security Operations Center (SOC) dashboard
on Kibana with:
1. Executive Header & Status Indicators
2. Real-Time KPI Cards (Failed Logins, Successful Logins, Total Events, Monitored Hosts)
3. Authentication Events Timeline (Time-series spike & brute-force detection)
4. Threat & Event Distribution Visualizations (Donut & Breakdown charts)
5. Target Host & Agent Breakdown
6. Real-Time Live Security Log Stream (Expandable event table)
7. Interactive Filters (Event Types & Hosts dropdowns + Time Slider)

Target Dashboard ID: c71e1675-d0b2-47d2-bb7f-a35d9b065005
"""

import sys
import json
import uuid
import base64
import getpass
import urllib.request
import urllib.error

# Ensure UTF-8 output encoding across all operating systems / terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


DASHBOARD_ID = "c71e1675-d0b2-47d2-bb7f-a35d9b065005"
SEARCH_ID = "security-logs-stream"


def get_data_view_id(kibana_host, headers):
    """Finds or confirms the security-logs-* Data View ID."""
    dv_id = "security-logs-dataview"
    try:
        req = urllib.request.Request(f"{kibana_host}/api/data_views", headers=headers)
        res = urllib.request.urlopen(req)
        dvs = json.loads(res.read()).get("data_view", [])
        for dv in dvs:
            if "security-logs" in dv.get("title", ""):
                return dv.get("id")
    except Exception as e:
        print(f"[-] Warning reading Data Views: {e}")
    return dv_id


def setup_saved_search(kibana_host, headers, dv_id):
    """Provisions a Saved Search object for the live event table."""
    search_obj = {
        "attributes": {
            "title": "Security Log Events Stream",
            "description": "Real-time authentication and security events from Linux and Windows clients",
            "columns": ["@timestamp", "event_type", "host.name", "message"],
            "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": dv_id
            }
        ]
    }

    url = f"{kibana_host}/api/saved_objects/search/{SEARCH_ID}?overwrite=true"
    req = urllib.request.Request(url, data=json.dumps(search_obj).encode(), headers=headers, method="POST")
    try:
        urllib.request.urlopen(req)
        print("[+] Live Search Stream object provisioned.")
    except Exception as e:
        print(f"[-] Warning provisioning Saved Search: {e}")


def build_dashboard(dv_id):
    """Constructs the complete SOC Dashboard structure."""
    panels = []
    references = []

    # 1. Executive Header Markdown (x=0, y=0, w=48, h=5)
    panels.append({
        "version": "8.9.0",
        "type": "visualization",
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 5, "i": "panel-header"},
        "panelIndex": "panel-header",
        "embeddableConfig": {
            "savedVis": {
                "title": "",
                "description": "",
                "type": "markdown",
                "params": {
                    "fontSize": 12,
                    "openLinksInNewTab": False,
                    "markdown": (
                        "### 🛡️ Security Operations Center (SOC) — Real-Time Log Monitoring Dashboard\n"
                        "**SIEM Authentication & Threat Detection** | Linux SSH (`/var/log/auth.log`) & Windows Security (`Event IDs 4624/4625`) | Engine: **ELK Stack 8.17.0**\n\n"
                        "🟢 **SIEM Engine:** ACTIVE &nbsp;&nbsp;|&nbsp;&nbsp; 🔍 **Data View:** `security-logs-*` &nbsp;&nbsp;|&nbsp;&nbsp; ⚡ **Rule Interval:** 10s &nbsp;&nbsp;|&nbsp;&nbsp; 🚨 **Alerts Monitor:** [View Active Alerts](/app/observability/alerts)"
                    )
                },
                "uiState": {},
                "data": {"aggs": [], "searchSource": {"query": {"query": "", "language": "kuery"}, "filter": []}}
            }
        }
    })

    # Helper: Metric Card
    def add_metric_card(panel_id, title, label, kuery_filter, x, y, w=12, h=6, operation="count", field="___records___"):
        layer_id = str(uuid.uuid4())
        col_id = str(uuid.uuid4())
        ref_name = f"{panel_id}:indexpattern-datasource-layer-{layer_id}"

        panel = {
            "version": "8.9.0",
            "type": "lens",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
            "panelIndex": panel_id,
            "embeddableConfig": {
                "attributes": {
                    "title": title,
                    "visualizationType": "lnsLegacyMetric",
                    "type": "lens",
                    "references": [
                        {"id": dv_id, "name": f"indexpattern-datasource-layer-{layer_id}", "type": "index-pattern"}
                    ],
                    "state": {
                        "visualization": {
                            "layerId": layer_id,
                            "accessor": col_id,
                            "layerType": "data",
                            "textAlign": "center",
                            "titlePosition": "bottom",
                            "size": "l"
                        },
                        "query": {"query": kuery_filter, "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    layer_id: {
                                        "columns": {
                                            col_id: {
                                                "label": label,
                                                "dataType": "number",
                                                "operationType": operation,
                                                "scale": "ratio",
                                                "sourceField": field,
                                                "isBucketed": False,
                                                "customLabel": True
                                            }
                                        },
                                        "columnOrder": [col_id]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        panels.append(panel)
        references.append({"type": "index-pattern", "id": dv_id, "name": ref_name})

    # 2. Top KPI Cards (Row 2, y=5, h=6)
    add_metric_card(
        panel_id="metric-failed",
        title="🚨 Failed Logins (SSH & RDP)",
        label="Failed Logins",
        kuery_filter='event_type : "*failed*" or message : "Failed password" or winlog.event_id : "4625"',
        x=0, y=5, w=12, h=6
    )
    add_metric_card(
        panel_id="metric-success",
        title="🟢 Successful Logins (SSH & RDP)",
        label="Successful Logins",
        kuery_filter='event_type : "*successful*" or message : "Accepted password" or winlog.event_id : "4624"',
        x=12, y=5, w=12, h=6
    )
    add_metric_card(
        panel_id="metric-total",
        title="📊 Total Security Events",
        label="Total Ingested Events",
        kuery_filter="",
        x=24, y=5, w=12, h=6
    )
    add_metric_card(
        panel_id="metric-hosts",
        title="💻 Monitored Target Hosts",
        label="Active Target Machines",
        kuery_filter="",
        x=36, y=5, w=12, h=6,
        operation="unique_count",
        field="host.name.keyword"
    )

    # 3. Main Time-Series: Authentication Events Timeline (x=0, y=11, w=32, h=14)
    time_layer_id = str(uuid.uuid4())
    time_col_time = str(uuid.uuid4())
    time_col_split = str(uuid.uuid4())
    time_col_metric = str(uuid.uuid4())
    panel_time_id = "panel-timeline"

    panels.append({
        "version": "8.9.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 11, "w": 32, "h": 14, "i": panel_time_id},
        "panelIndex": panel_time_id,
        "embeddableConfig": {
            "attributes": {
                "title": "📈 Authentication Events Timeline (Spike & Attack Rate)",
                "visualizationType": "lnsXY",
                "type": "lens",
                "references": [
                    {"type": "index-pattern", "id": dv_id, "name": f"indexpattern-datasource-layer-{time_layer_id}"}
                ],
                "state": {
                    "visualization": {
                        "legend": {"isVisible": True, "position": "right"},
                        "preferredSeriesType": "bar_stacked",
                        "layers": [{
                            "layerId": time_layer_id,
                            "xAccessor": time_col_time,
                            "accessors": [time_col_metric],
                            "splitAccessor": time_col_split,
                            "seriesType": "bar_stacked",
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                time_layer_id: {
                                    "columns": {
                                        time_col_time: {
                                            "label": "Timestamp",
                                            "dataType": "date",
                                            "operationType": "date_histogram",
                                            "scale": "interval",
                                            "sourceField": "@timestamp",
                                            "isBucketed": True,
                                            "params": {"interval": "auto"}
                                        },
                                        time_col_split: {
                                            "label": "Event Type",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "scale": "ordinal",
                                            "sourceField": "event_type.keyword",
                                            "isBucketed": True,
                                            "params": {
                                                "size": 5,
                                                "orderBy": {"type": "column", "columnId": time_col_metric},
                                                "orderDirection": "desc",
                                                "otherBucket": True,
                                                "missingBucket": False
                                            }
                                        },
                                        time_col_metric: {
                                            "label": "Event Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "scale": "ratio",
                                            "sourceField": "___records___",
                                            "isBucketed": False,
                                            "params": {"emptyAsNull": True}
                                        }
                                    },
                                    "columnOrder": [time_col_time, time_col_split, time_col_metric]
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    references.append({"type": "index-pattern", "id": dv_id, "name": f"{panel_time_id}:indexpattern-datasource-layer-{time_layer_id}"})

    # 4. Donut Chart: Event Types Distribution (x=32, y=11, w=16, h=14)
    pie_layer_id = str(uuid.uuid4())
    pie_col_group = str(uuid.uuid4())
    pie_col_metric = str(uuid.uuid4())
    panel_pie_id = "panel-event-types"

    panels.append({
        "version": "8.9.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 11, "w": 16, "h": 14, "i": panel_pie_id},
        "panelIndex": panel_pie_id,
        "embeddableConfig": {
            "attributes": {
                "title": "🍩 Threat vs Legitimate Event Ratio",
                "visualizationType": "lnsPie",
                "type": "lens",
                "references": [
                    {"type": "index-pattern", "id": dv_id, "name": f"indexpattern-datasource-layer-{pie_layer_id}"}
                ],
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": pie_layer_id,
                            "groups": [pie_col_group],
                            "metric": pie_col_metric,
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                pie_layer_id: {
                                    "columns": {
                                        pie_col_group: {
                                            "label": "Event Classification",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "scale": "ordinal",
                                            "sourceField": "event_type.keyword",
                                            "isBucketed": True,
                                            "params": {
                                                "size": 5,
                                                "orderBy": {"type": "column", "columnId": pie_col_metric},
                                                "orderDirection": "desc",
                                                "otherBucket": True,
                                                "missingBucket": False
                                            }
                                        },
                                        pie_col_metric: {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "scale": "ratio",
                                            "sourceField": "___records___",
                                            "isBucketed": False,
                                            "params": {"emptyAsNull": True}
                                        }
                                    },
                                    "columnOrder": [pie_col_group, pie_col_metric]
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    references.append({"type": "index-pattern", "id": dv_id, "name": f"{panel_pie_id}:indexpattern-datasource-layer-{pie_layer_id}"})

    # 5. Events by Target Host (x=0, y=25, w=16, h=12)
    host_layer_id = str(uuid.uuid4())
    host_col_group = str(uuid.uuid4())
    host_col_metric = str(uuid.uuid4())
    panel_host_id = "panel-target-hosts"

    panels.append({
        "version": "8.9.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 25, "w": 16, "h": 12, "i": panel_host_id},
        "panelIndex": panel_host_id,
        "embeddableConfig": {
            "attributes": {
                "title": "💻 Log Volume by Target Host",
                "visualizationType": "lnsXY",
                "type": "lens",
                "references": [
                    {"type": "index-pattern", "id": dv_id, "name": f"indexpattern-datasource-layer-{host_layer_id}"}
                ],
                "state": {
                    "visualization": {
                        "legend": {"isVisible": False},
                        "preferredSeriesType": "bar_horizontal",
                        "layers": [{
                            "layerId": host_layer_id,
                            "xAccessor": host_col_group,
                            "accessors": [host_col_metric],
                            "seriesType": "bar_horizontal",
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                host_layer_id: {
                                    "columns": {
                                        host_col_group: {
                                            "label": "Target Host",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "scale": "ordinal",
                                            "sourceField": "host.name.keyword",
                                            "isBucketed": True,
                                            "params": {
                                                "size": 5,
                                                "orderBy": {"type": "column", "columnId": host_col_metric},
                                                "orderDirection": "desc",
                                                "otherBucket": False,
                                                "missingBucket": False
                                            }
                                        },
                                        host_col_metric: {
                                            "label": "Events",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "scale": "ratio",
                                            "sourceField": "___records___",
                                            "isBucketed": False,
                                            "params": {"emptyAsNull": True}
                                        }
                                    },
                                    "columnOrder": [host_col_group, host_col_metric]
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    references.append({"type": "index-pattern", "id": dv_id, "name": f"{panel_host_id}:indexpattern-datasource-layer-{host_layer_id}"})

    # 6. Top Event Types by Volume (x=16, y=25, w=16, h=12)
    ev_layer_id = str(uuid.uuid4())
    ev_col_group = str(uuid.uuid4())
    ev_col_metric = str(uuid.uuid4())
    panel_ev_id = "panel-threat-categories"

    panels.append({
        "version": "8.9.0",
        "type": "lens",
        "gridData": {"x": 16, "y": 25, "w": 16, "h": 12, "i": panel_ev_id},
        "panelIndex": panel_ev_id,
        "embeddableConfig": {
            "attributes": {
                "title": "🎯 Security Events by Category",
                "visualizationType": "lnsXY",
                "type": "lens",
                "references": [
                    {"type": "index-pattern", "id": dv_id, "name": f"indexpattern-datasource-layer-{ev_layer_id}"}
                ],
                "state": {
                    "visualization": {
                        "legend": {"isVisible": False},
                        "preferredSeriesType": "bar",
                        "layers": [{
                            "layerId": ev_layer_id,
                            "xAccessor": ev_col_group,
                            "accessors": [ev_col_metric],
                            "seriesType": "bar",
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                ev_layer_id: {
                                    "columns": {
                                        ev_col_group: {
                                            "label": "Event Type",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "scale": "ordinal",
                                            "sourceField": "event_type.keyword",
                                            "isBucketed": True,
                                            "params": {
                                                "size": 5,
                                                "orderBy": {"type": "column", "columnId": ev_col_metric},
                                                "orderDirection": "desc",
                                                "otherBucket": False,
                                                "missingBucket": False
                                            }
                                        },
                                        ev_col_metric: {
                                            "label": "Event Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "scale": "ratio",
                                            "sourceField": "___records___",
                                            "isBucketed": False,
                                            "params": {"emptyAsNull": True}
                                        }
                                    },
                                    "columnOrder": [ev_col_group, ev_col_metric]
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    references.append({"type": "index-pattern", "id": dv_id, "name": f"{panel_ev_id}:indexpattern-datasource-layer-{ev_layer_id}"})

    # 7. Shipper Agent Distribution (x=32, y=25, w=16, h=12)
    ag_layer_id = str(uuid.uuid4())
    ag_col_group = str(uuid.uuid4())
    ag_col_metric = str(uuid.uuid4())
    panel_ag_id = "panel-shipper-distribution"

    panels.append({
        "version": "8.9.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 25, "w": 16, "h": 12, "i": panel_ag_id},
        "panelIndex": panel_ag_id,
        "embeddableConfig": {
            "attributes": {
                "title": "📡 Beats Shipper Agent Breakdown",
                "visualizationType": "lnsPie",
                "type": "lens",
                "references": [
                    {"type": "index-pattern", "id": dv_id, "name": f"indexpattern-datasource-layer-{ag_layer_id}"}
                ],
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": ag_layer_id,
                            "groups": [ag_col_group],
                            "metric": ag_col_metric,
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                ag_layer_id: {
                                    "columns": {
                                        ag_col_group: {
                                            "label": "Shipper Agent",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "scale": "ordinal",
                                            "sourceField": "agent.type.keyword",
                                            "isBucketed": True,
                                            "params": {
                                                "size": 5,
                                                "orderBy": {"type": "column", "columnId": ag_col_metric},
                                                "orderDirection": "desc",
                                                "otherBucket": False,
                                                "missingBucket": False
                                            }
                                        },
                                        ag_col_metric: {
                                            "label": "Events",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "scale": "ratio",
                                            "sourceField": "___records___",
                                            "isBucketed": False,
                                            "params": {"emptyAsNull": True}
                                        }
                                    },
                                    "columnOrder": [ag_col_group, ag_col_metric]
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    references.append({"type": "index-pattern", "id": dv_id, "name": f"{panel_ag_id}:indexpattern-datasource-layer-{ag_layer_id}"})

    # 8. Real-Time Live Security Log Stream (Discover Embedded Table) (x=0, y=37, w=48, h=16)
    panel_stream_id = "panel-live-stream"
    panels.append({
        "type": "search",
        "panelIndex": panel_stream_id,
        "gridData": {"x": 0, "y": 37, "w": 48, "h": 16, "i": panel_stream_id},
        "panelRefName": f"panel_{panel_stream_id}",
        "embeddableConfig": {}
    })
    references.append({
        "name": f"panel_{panel_stream_id}",
        "type": "search",
        "id": SEARCH_ID
    })

    # Interactive Filter Controls
    control_group = {
        "chainingSystem": "HIERARCHICAL",
        "controlStyle": "oneLine",
        "ignoreParentSettingsJSON": json.dumps({
            "ignoreFilters": False,
            "ignoreQuery": False,
            "ignoreTimerange": False,
            "ignoreValidations": False
        }),
        "panelsJSON": json.dumps({
            "ctrl-time": {
                "type": "timeSlider",
                "order": 0,
                "width": "large",
                "grow": True,
                "explicitInput": {
                    "id": "ctrl-time",
                    "title": "Time Slider"
                }
            },
            "ctrl-event-type": {
                "type": "optionsListControl",
                "order": 1,
                "width": "medium",
                "grow": True,
                "explicitInput": {
                    "id": "ctrl-event-type",
                    "fieldName": "event_type.keyword",
                    "title": "Filter Event Type",
                    "selectedOptions": []
                }
            },
            "ctrl-host": {
                "type": "optionsListControl",
                "order": 2,
                "width": "medium",
                "grow": True,
                "explicitInput": {
                    "id": "ctrl-host",
                    "fieldName": "host.name.keyword",
                    "title": "Filter Target Host",
                    "selectedOptions": []
                }
            }
        }),
        "showApplySelections": False
    }

    # Add control group references to data view
    references.append({"name": "controlGroup_ctrl-event-type:optionsListDataView", "type": "index-pattern", "id": dv_id})
    references.append({"name": "controlGroup_ctrl-host:optionsListDataView", "type": "index-pattern", "id": dv_id})

    dashboard_obj = {
        "attributes": {
            "title": "Security Dashboard",
            "description": "SOC Security Log Monitoring Dashboard for Linux SSH and Windows RDP authentication events",
            "timeRestore": True,
            "timeFrom": "now-24h",
            "timeTo": "now",
            "optionsJSON": json.dumps({
                "useMargins": True,
                "syncColors": True,
                "syncCursor": True,
                "syncTooltips": True,
                "hidePanelTitles": False
            }),
            "controlGroupInput": control_group,
            "panelsJSON": json.dumps(panels)
        },
        "references": references
    }

    return dashboard_obj


def deploy_dashboard(kibana_host, admin_user, admin_pass):
    """Deploys or updates the SOC Security Dashboard in Kibana."""
    auth_header = "Basic " + base64.b64encode(f"{admin_user}:{admin_pass}".encode()).decode()
    headers = {
        "Authorization": auth_header,
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }

    print("\n=============================================")
    print(" SOC Professional Security Dashboard Setup")
    print(f" Target Kibana: {kibana_host}")
    print("=============================================")

    # 1. Resolve Data View
    dv_id = get_data_view_id(kibana_host, headers)
    print(f"[+] Using Data View ID: '{dv_id}'")

    # 2. Provision Live Saved Search Stream
    setup_saved_search(kibana_host, headers, dv_id)

    # 3. Build Dashboard Object
    print("[*] Generating SOC Dashboard layout & Lens visualizations...")
    dash_payload = build_dashboard(dv_id)

    # 4. Upload Dashboard to Kibana
    dash_url = f"{kibana_host}/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true"
    dash_req = urllib.request.Request(dash_url, data=json.dumps(dash_payload).encode(), headers=headers, method="POST")

    try:
        urllib.request.urlopen(dash_req)
        print(f"[+] Professional SOC Dashboard deployed successfully!")
        print(f"👉 Direct Dashboard URL: {kibana_host}/app/dashboards#/view/{DASHBOARD_ID}")
        return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error deploying dashboard ({e.code}): {e.read().decode()}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Error deploying dashboard: {e}", file=sys.stderr)
        return False


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
        print("[-] Error: Usage: python3 setup_dashboard.py <kibana_url> <admin_username> <admin_password>", file=sys.stderr)
        sys.exit(1)

    success = deploy_dashboard(kibana_host, admin_user, admin_pass)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
