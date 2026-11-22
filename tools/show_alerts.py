#!/usr/bin/env python3
"""
show_alerts.py — résumé des alertes honeypot sur le manager (SRV01)

  sudo python3 tools/show_alerts.py            # tout alerts.json
  sudo python3 tools/show_alerts.py --since 15 # 15 dernières minutes
"""
import collections
import json
import sys
from datetime import datetime, timedelta, timezone

path = "/var/ossec/logs/alerts/alerts.json"
since = None
if "--since" in sys.argv:
    since = datetime.now(timezone.utc) - timedelta(minutes=int(sys.argv[sys.argv.index("--since") + 1]))

rules = collections.Counter()
last = {}
per_hp = collections.Counter()
ips, users, pwds, cmds = (collections.Counter() for _ in range(4))
for line in open(path, errors="replace"):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    r = d.get("rule", {})
    rid = r.get("id", "")
    if not rid.startswith("10") or len(rid) != 6 or rid == "100100":
        continue
    if since:
        try:
            if datetime.strptime(d["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") < since:
                continue
        except (KeyError, ValueError):
            continue
    data = d.get("data", {})
    hp = data.get("honeypot") or ("web" if "web" in r.get("groups", []) else "nix01 (privesc/FIM)")
    rules[rid] += 1
    per_hp[hp] += 1
    last[rid] = (r.get("level"), r.get("description"))
    if data.get("srcip"):
        ips[data["srcip"]] += 1
    if data.get("event_type") == "login_attempt":
        users[data.get("username", "?")] += 1
        pwds[data.get("password", "?")] += 1
    if data.get("event_type") == "command":
        cmds[f"[{hp}] {data.get('command', '')[:70]}"] += 1


def top(title, counter, n=8):
    print(f"\n--- {title} ---")
    for k, v in counter.most_common(n):
        print(f"  {v:>5}  {k}")


print("=== ALERTES HONEYPOT ===")
for rid in sorted(rules):
    lvl, desc = last[rid]
    print(f"{rid}  L{str(lvl):<3} n={rules[rid]:<5} {desc}")
print(f"règles distinctes : {len(rules)}   total : {sum(rules.values())}")
top("Par honeypot", per_hp)
top("Top IP source", ips)
top("Top usernames", users)
top("Top mots de passe", pwds)
top("Top commandes", cmds, 12)
