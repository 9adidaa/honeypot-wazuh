import json, collections, sys
path = "/var/ossec/logs/alerts/alerts.json"
c = collections.Counter(); last = {}
for line in open(path):
    try:
        d = json.loads(line)
    except Exception:
        continue
    r = d.get("rule", {}); rid = r.get("id", "")
    if rid.startswith("100") and rid != "100100":
        c[rid] += 1
        last[rid] = (d.get("timestamp", "")[:19], r.get("level"), r.get("description"))
print("=== CUSTOM RULE ALERTS (live) ===")
for rid in sorted(c):
    t, lvl, desc = last[rid]
    print(f"{rid}  L{str(lvl):<3} n={c[rid]:<4} {desc}")
print("distinct:", len(c), " total:", sum(c.values()))
