#!/usr/bin/env python3
"""
build_dashboard.py — génère wazuh/dashboard/honeypot-dashboard.ndjson

Objets "saved objects" (OpenSearch Dashboards / Wazuh dashboard) :
  - un index pattern dédié (titre wazuh-alerts-*) pour ne pas dépendre de celui
    que l'appli Wazuh crée au premier login
  - les visualisations du tableau de bord "Honeypot"
  - le dashboard lui-même

  python3 tools/build_dashboard.py            # régénère le fichier
  python3 tools/build_dashboard.py --check    # code retour 1 si le fichier n'est pas à jour

Importé automatiquement par deploy/dashboard.sh (POST /api/saved_objects/_import).
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "wazuh", "dashboard", "honeypot-dashboard.ndjson")

INDEX_ID = "hp-wazuh-alerts"
BASE_QUERY = "rule.groups:honeypot"
HONEYPOTS = [  # libellé -> requête KQL (le web n'a pas de champ data.honeypot)
    ("web (SweetBuzz)", "rule.groups:web and rule.groups:honeypot"),
    ("ssh", "data.honeypot:ssh"),
    ("ftp", "data.honeypot:ftp"),
    ("redis", "data.honeypot:redis"),
    ("privesc / FIM (NIX01)", "rule.groups:privilege_escalation or rule.groups:syscheck"),
]


def search_source(query=BASE_QUERY):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})


def filters_agg(aid="2", schema="segment"):
    return {"id": aid, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"query": q, "language": "kuery"}, "label": label}
                                   for label, q in HONEYPOTS]}}


def terms(aid, field, size=10, schema="bucket", label=None):
    return {"id": aid, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "size": size, "order": "desc", "orderBy": "1",
                       "otherBucket": False, "missingBucket": False, "customLabel": label or ""}}


COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def vis(vid, title, vtype, aggs, params, query=BASE_QUERY):
    return {
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps({"title": title, "type": vtype, "aggs": aggs, "params": params}),
            "uiStateJSON": "{}", "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": INDEX_ID}],
        "migrationVersion": {"visualization": "7.10.0"},
    }


def table(vid, title, field, label, size=10, query=BASE_QUERY):
    return vis(vid, title, "table", [COUNT, terms("2", field, size, label=label)],
               {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                "showTotal": False, "totalFunc": "sum", "percentageCol": ""}, query)


def objects():
    objs = [{
        "id": INDEX_ID, "type": "index-pattern",
        "attributes": {"title": "wazuh-alerts-*", "timeFieldName": "timestamp"},
        "references": [], "migrationVersion": {"index-pattern": "7.6.0"},
    }]
    pie_params = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                  "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}
    v = [
        vis("hp-vis-metrics", "Honeypot - Total alerts / unique attackers", "metric",
            [COUNT, {"id": "3", "enabled": True, "type": "cardinality", "schema": "metric",
                     "params": {"field": "data.srcip", "customLabel": "Unique source IPs"}}],
            {"addTooltip": True, "addLegend": False, "type": "metric",
             "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                        "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                        "labels": {"show": True}, "invertColors": False,
                        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}}),
        vis("hp-vis-per-honeypot", "Honeypot - Alerts per honeypot", "pie", [COUNT, filters_agg()], pie_params),
        vis("hp-vis-timeline", "Honeypot - Alerts timeline", "histogram",
            [COUNT,
             {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
              "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True, "interval": "auto",
                         "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
             filters_agg("3", "group")],
            {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "right",
             "times": [], "addTimeMarker": False,
             "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                               "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "truncate": 100},
                               "title": {}}],
             "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                            "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                            "title": {"text": "Alerts"}}],
             "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                               "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                               "drawLinesBetweenPoints": True, "showCircles": True}],
             "grid": {"categoryLines": False}}),
        table("hp-vis-top-ips", "Honeypot - Top source IPs", "data.srcip", "Source IP"),
        table("hp-vis-top-users", "Honeypot - Top usernames", "data.username", "Username",
              query=BASE_QUERY + " and data.event_type:login_attempt"),
        table("hp-vis-top-passwords", "Honeypot - Top passwords", "data.password", "Password",
              query=BASE_QUERY + " and data.event_type:login_attempt"),
        table("hp-vis-top-commands", "Honeypot - Top commands (SSH / FTP / Redis)", "data.command", "Command", 15,
              query=BASE_QUERY + " and data.event_type:command"),
        table("hp-vis-top-rules", "Honeypot - Top rules", "rule.description", "Rule", 15),
        vis("hp-vis-mitre", "Honeypot - MITRE ATT&CK techniques", "pie",
            [COUNT, terms("2", "rule.mitre.technique", 10, schema="segment")], pie_params),
        table("hp-vis-uploads", "Honeypot - FTP uploads (sha256)", "data.sha256", "sha256",
              query=BASE_QUERY + " and data.event_type:file_upload"),
    ]
    objs += v
    layout = [  # (id, x, y, w, h) sur une grille de 48 colonnes
        ("hp-vis-metrics", 0, 0, 12, 10), ("hp-vis-per-honeypot", 12, 0, 16, 10), ("hp-vis-mitre", 28, 0, 20, 10),
        ("hp-vis-timeline", 0, 10, 48, 12),
        ("hp-vis-top-ips", 0, 22, 16, 14), ("hp-vis-top-users", 16, 22, 16, 14), ("hp-vis-top-passwords", 32, 22, 16, 14),
        ("hp-vis-top-commands", 0, 36, 28, 16), ("hp-vis-top-rules", 28, 36, 20, 16),
        ("hp-vis-uploads", 0, 52, 48, 10),
    ]
    panels, refs = [], []
    for i, (vid, x, y, w, h) in enumerate(layout):
        panels.append({"version": "2.19.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                       "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})
    objs.append({
        "id": "hp-dashboard", "type": "dashboard",
        "attributes": {
            "title": "Honeypot", "description": "Honeypots SweetBuzz (web), SSH, FTP, Redis + privesc NIX01",
            "hits": 0, "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1, "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs, "migrationVersion": {"dashboard": "7.9.3"},
    })
    return objs


def render():
    return "".join(json.dumps(o, separators=(",", ":"), sort_keys=True) + "\n" for o in objects())


if __name__ == "__main__":
    out = render()
    if "--check" in sys.argv:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        sys.exit(0 if cur == out else 1)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print(f"{OUT}: {len(objects())} objets")
