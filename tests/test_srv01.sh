#!/usr/bin/env bash
# =============================================================================
# test_srv01.sh — vérifie le manager Wazuh (SRV01) + les règles du honeypot
#
#   sudo bash tests/test_srv01.sh               # services + règles (wazuh-logtest)
#   sudo bash tests/test_srv01.sh --e2e         # + vraies attaques sur NIX01 (web, SSH,
#                                               #   FTP, Redis via tools/attack_demo.py) -> alertes
#   sudo bash tests/test_srv01.sh --since 10    # alertes privesc/FIM des 10 dernières min
#                                               # (après test_nix01.sh --trigger)
# Env: NIX01_IP (défaut 192.168.56.101), AGENT_NAME (défaut nix01)
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CASES="$HERE/cases.tsv"
HP_CASES="$HERE/hp_cases.tsv"
ATTACK="$HERE/../tools/attack_demo.py"
NIX01_IP="${NIX01_IP:-192.168.56.101}"
AGENT_NAME="${AGENT_NAME:-nix01}"
OSSEC=/var/ossec
ALERTS="$OSSEC/logs/alerts/alerts.json"
LOGTEST="$OSSEC/bin/wazuh-logtest"
OKN=0; FAILN=0; WARNN=0

ok()   { echo -e "  \e[32m[OK]\e[0m   $*"; OKN=$((OKN+1)); }
fail() { echo -e "  \e[31m[FAIL]\e[0m $*"; FAILN=$((FAILN+1)); }
warn() { echo -e "  \e[33m[WARN]\e[0m $*"; WARNN=$((WARNN+1)); }
sec()  { echo -e "\n\e[1m== $* ==\e[0m"; }
check(){ local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else fail "$msg"; fi; }

[[ $EUID -eq 0 ]] || { echo "Lancer en root: sudo bash $0"; exit 2; }
[[ -f "$CASES" ]] || { echo "cases.tsv introuvable à côté du script"; exit 2; }

# Renvoie l'ID de la règle déclenchée par une ligne (phase 3 de wazuh-logtest)
logtest_rule() {
  printf '%s\n' "$1" | timeout 60 "$LOGTEST" 2>&1 \
    | awk '/Phase 3/{f=1} f && /^[[:space:]]*id: /{gsub(/[^0-9]/,""); print; exit}'
}
logtest_decoder() {
  printf '%s\n' "$1" | timeout 60 "$LOGTEST" 2>&1 \
    | awk '/Phase 2/{f=1} f && /^[[:space:]]*name: /{gsub(/.*name: |'"'"'/,""); print; exit}'
}

# -----------------------------------------------------------------------------
sec "1. Services Wazuh"
for s in wazuh-manager wazuh-indexer wazuh-dashboard; do
  check "$s actif" systemctl is-active --quiet "$s"
done
for p in 1514 1515 55000 9200 443; do
  check "port $p en écoute" bash -c "ss -ltn | grep -q ':$p '"
done

# -----------------------------------------------------------------------------
sec "2. Fichiers + configuration"
check "décodeur installé"   test -s "$OSSEC/etc/decoders/honeypot_decoders.xml"
check "règles installées"   test -s "$OSSEC/etc/rules/honeypot_rules.xml"
check "règles SSH/FTP/Redis installées" test -s "$OSSEC/etc/rules/honeypot_services_rules.xml"
check "logall activé"       grep -q "<logall>yes</logall>" "$OSSEC/etc/ossec.conf"
if out=$("$OSSEC/bin/wazuh-analysisd" -t 2>&1); then
  ok "wazuh-analysisd -t : config + règles valides"
else
  fail "wazuh-analysisd -t : $(grep -iE 'error|critical' <<<"$out" | head -3)"
fi
if grep -iE "(error|warning).*(honeypot|1001[0-9]{2}|1002[0-9]{2}|100300|1003[0-9]{2}|1004[0-9]{2})" "$OSSEC/logs/ossec.log" | tail -3 | grep -q .; then
  warn "messages liés aux règles honeypot dans ossec.log :"
  grep -iE "(error|warning).*(honeypot|1001[0-9]{2}|1002[0-9]{2}|100300|1003[0-9]{2}|1004[0-9]{2})" "$OSSEC/logs/ossec.log" | tail -3 | sed 's/^/         /'
else
  ok "aucune erreur liée aux règles honeypot dans ossec.log"
fi

# -----------------------------------------------------------------------------
sec "3. Agent $AGENT_NAME"
agents=$("$OSSEC/bin/agent_control" -l 2>/dev/null)
if grep -E "Name: $AGENT_NAME," <<<"$agents" | grep -q "Active"; then
  ok "agent $AGENT_NAME enregistré et Active"
else
  fail "agent $AGENT_NAME absent ou inactif : $(grep -E "Name: $AGENT_NAME," <<<"$agents" || echo 'non trouvé')"
fi

# -----------------------------------------------------------------------------
sec "4. Règles web (wazuh-logtest, sans trafic)"
dec=$(logtest_decoder "HONEYPOT-ACCESS src=203.0.113.50 method=GET path=/ status=200 body=- ua=curl xff=-")
[[ "$dec" == "hp-access" ]] && ok "décodeur hp-access reconnu" || fail "décodeur: '$dec' (attendu hp-access)"

while IFS=$'\t' read -r name exp method path data ua logline; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  got=$(logtest_rule "$logline")
  [[ "$got" == "$exp" ]] && ok "$(printf '%-18s -> %s' "$name" "$got")" \
                         || fail "$(printf '%-18s -> %s (attendu %s)' "$name" "${got:-aucune}" "$exp")"
done < "$CASES"

# Brute force : 10 x 404 depuis la même IP dans la même session logtest
bf=$(for i in $(seq 1 10); do
       echo "HONEYPOT-ACCESS src=203.0.113.77 method=GET path=/bf$i status=404 body=- ua=curl/8.5.0 xff=-"
     done | timeout 90 "$LOGTEST" 2>&1)
grep -qE "id: '100191'" <<<"$bf" && ok "brute_force_404    -> 100191" \
  || fail "brute_force_404    -> 100191 jamais déclenchée (vérifier que le décodeur extrait bien 'srcip')"

# -----------------------------------------------------------------------------
sec "4b. Règles SSH/FTP/Redis (wazuh-logtest, événements JSON de tests/hp_cases.tsv)"
while IFS=$'\t' read -r name exp json; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  got=$(logtest_rule "$json")
  [[ "$got" == "$exp" ]] && ok "$(printf '%-22s -> %s' "$name" "$got")" \
                         || fail "$(printf '%-22s -> %s (attendu %s)' "$name" "${got:-aucune}" "$exp")"
done < "$HP_CASES"

# Corrélations : plusieurs événements dans la même session wazuh-logtest
hp_json() { # $1=honeypot $2=event_type $3=session $4..=paires "clé":"valeur" JSON supplémentaires
  local hp="$1" et="$2" sid="$3"; shift 3
  local extra=""; [[ $# -gt 0 ]] && extra=",$(IFS=,; echo "$*")"
  printf '{"timestamp":"2026-11-22T10:00:00.000000+00:00","honeypot":"%s","event_type":"%s","srcip":"203.0.113.88","src_port":40000,"session":"%s"%s}\n' \
    "$hp" "$et" "$sid" "$extra"
}
for hp in ssh ftp redis; do
  bf=$(for i in $(seq 1 8); do
         hp_json "$hp" login_attempt "bf$hp$i" '"username":"root"' "\"password\":\"pw$i\"" '"success":false'
       done | timeout 90 "$LOGTEST" 2>&1)
  grep -qE "id: '100410'" <<<"$bf" && ok "brute force $hp (8 échecs) -> 100410" \
    || fail "brute force $hp (8 échecs) -> 100410 jamais déclenchée"
done
corr=$( { hp_json redis command s1 '"command":"CONFIG SET dir /var/spool/cron/crontabs"' '"verb":"CONFIG"'
          hp_json redis command s1 '"command":"SAVE"' '"verb":"SAVE"'; } | timeout 90 "$LOGTEST" 2>&1)
grep -qE "id: '100446'" <<<"$corr" && ok "Redis CONFIG SET dir + SAVE (même session) -> 100446" \
  || fail "Redis CONFIG SET dir + SAVE (même session) -> 100446 jamais déclenchée"

# -----------------------------------------------------------------------------
sec "5. Règles privesc (wazuh-logtest, événements auditd simulés)"
audit_line() { # $1=syscall $2=comm $3=exe $4=key
  echo "type=SYSCALL msg=audit(1732000000.123:4242): arch=c000003e syscall=$1 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=1 ppid=1200 pid=1300 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=3 comm=\"$2\" exe=\"$3\" key=\"$4\""
}
while read -r exp sc comm exe key; do
  got=$(logtest_rule "$(audit_line "$sc" "$comm" "$exe" "$key")")
  [[ "$got" == "$exp" ]] && ok "$(printf '%-12s -> %s' "$key" "$got")" \
                         || fail "$(printf '%-12s -> %s (attendu %s)' "$key" "${got:-aucune}" "$exp")"
done <<'EOF'
100210 257 vi        /usr/bin/vim.basic      hp_identity
100211 257 visudo    /usr/sbin/visudo        hp_sudoers
100212 257 crontab   /usr/bin/crontab        hp_cron
100213 257 tee       /usr/bin/tee            hp_preload
100214 59  sudo      /usr/bin/sudo           hp_exec
100215 105 python3   /usr/bin/python3.10     hp_setuid
100216 101 gdb       /usr/bin/gdb            hp_ptrace
100217 165 mount     /usr/bin/mount          hp_mount
100218 59  find      /usr/bin/find           hp_find
EOF

# -----------------------------------------------------------------------------
if [[ "${1:-}" == "--e2e" ]]; then
  sec "6. Bout en bout : attaques réelles -> NIX01 ($NIX01_IP:5000) -> alertes"
  RUNID="hptest$(date +%s)"
  check "SweetBuzz joignable depuis SRV01" curl -s -o /dev/null --max-time 5 "http://$NIX01_IP:5000/"
  while IFS=$'\t' read -r name exp method path data ua logline; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    args=(-s -o /dev/null --max-time 5 --path-as-is -X "$method" -A "$ua $RUNID-$name")
    [[ "$data" != "-" ]] && args+=(--data-raw "$data")
    curl "${args[@]}" "http://$NIX01_IP:5000$path"
  done < "$CASES"
  for i in $(seq 1 10); do
    curl -s -o /dev/null --max-time 5 -A "curl/8.5.0 $RUNID-bruteforce" "http://$NIX01_IP:5000/bf-$i"
  done
  echo "  ... attente des alertes (max 60 s)"
  for _ in $(seq 1 30); do
    n=$(grep -c "$RUNID" "$ALERTS" 2>/dev/null || echo 0)
    [[ "$n" -ge 9 ]] && { sleep 5; break; }
    sleep 2
  done
  python3 - "$ALERTS" "$RUNID" "$CASES" <<'PY'
import json, re, sys
alerts, runid, cases = sys.argv[1:4]
seen = {}
for ln in open(alerts, errors="replace"):
    if runid not in ln:
        continue
    try:
        a = json.loads(ln)
    except ValueError:
        continue
    m = re.search(re.escape(runid) + r"-(\w+)", a.get("full_log", ""))
    if m:
        seen.setdefault(m.group(1), set()).add(a["rule"]["id"])
exp = {}
for ln in open(cases):
    if ln.strip() and not ln.startswith("#"):
        f = ln.split("\t")
        exp[f[0]] = f[1]
exp["bruteforce"] = "100191"
okn = failn = 0
for name, rid in exp.items():
    got = seen.get(name, set())
    if rid in got:
        okn += 1
        print(f"  \033[32m[OK]\033[0m   {name:<18} -> alerte {rid}")
    else:
        failn += 1
        print(f"  \033[31m[FAIL]\033[0m {name:<18} -> {sorted(got) or 'aucune alerte'} (attendu {rid})")
print(f"E2E {okn} OK {failn} FAIL")
sys.exit(1 if failn else 0)
PY
  if [[ $? -eq 0 ]]; then OKN=$((OKN+1)); else FAILN=$((FAILN+1)); fi

  sec "6b. Bout en bout : attaques SSH/FTP/Redis (tools/attack_demo.py) -> alertes"
  if ! python3 -c "import paramiko" 2>/dev/null && ! command -v sshpass >/dev/null; then
    echo "  ... installation de sshpass (client SSH de l'attaque simulée)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass >/dev/null 2>&1 || warn "sshpass non installable : partie SSH sautée"
  fi
  START=$(date -u +%s)
  if python3 "$ATTACK" --target "$NIX01_IP" --only ssh,ftp,redis --quiet; then
    ok "attaque simulée exécutée (ssh, ftp, redis)"
  else
    fail "attack_demo.py a rencontré des erreurs (voir ci-dessus)"
  fi
  echo "  ... attente des alertes (max 120 s)"
  python3 - "$ALERTS" "$START" "$AGENT_NAME" <<'PY'
import json, sys, time
from datetime import datetime
alerts, start, agent = sys.argv[1], int(sys.argv[2]), sys.argv[3]
want = {
    "ssh": {"100401", "100402", "100410", "100404", "100423", "100421", "100422"},
    "ftp": {"100401", "100402", "100410", "100404", "100432", "100431"},
    "redis": {"100401", "100402", "100410", "100440", "100441", "100442", "100443", "100444",
              "100445", "100446", "100447"},
}


def collect():
    seen = {k: set() for k in want}
    for ln in open(alerts, errors="replace"):
        if '"honeypot"' not in ln:
            continue
        try:
            a = json.loads(ln)
            ts = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
        except (ValueError, KeyError):
            continue
        hp = a.get("data", {}).get("honeypot")
        if ts >= start - 5 and hp in seen and a.get("agent", {}).get("name") == agent:
            seen[hp].add(a["rule"]["id"])
    return seen


end = time.time() + 120
while True:
    seen = collect()
    if all(want[k] <= seen[k] for k in want) or time.time() > end:
        break
    time.sleep(5)
bad = 0
for hp, rules in want.items():
    for rid in sorted(rules):
        if rid in seen[hp]:
            print(f"  \033[32m[OK]\033[0m   {hp:<6} -> alerte {rid}")
        else:
            bad += 1
            print(f"  \033[31m[FAIL]\033[0m {hp:<6} -> alerte {rid} absente (vues : {sorted(seen[hp]) or 'aucune'})")
sys.exit(1 if bad else 0)
PY
  if [[ $? -eq 0 ]]; then OKN=$((OKN+1)); else FAILN=$((FAILN+1)); fi
fi

# -----------------------------------------------------------------------------
if [[ "${1:-}" == "--since" ]]; then
  MIN="${2:-10}"
  sec "6. Alertes privesc/FIM de $AGENT_NAME sur les $MIN dernières minutes"
  python3 - "$ALERTS" "$MIN" "$AGENT_NAME" <<'PY'
import json, sys
from datetime import datetime, timedelta, timezone
alerts, mins, agent = sys.argv[1], int(sys.argv[2]), sys.argv[3]
since = datetime.now(timezone.utc) - timedelta(minutes=mins)
count = {}
for ln in open(alerts, errors="replace"):
    try:
        a = json.loads(ln)
        ts = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    except (ValueError, KeyError):
        continue
    if ts < since or a.get("agent", {}).get("name") != agent:
        continue
    rid = a["rule"]["id"]
    if rid.startswith("1002") or rid == "100300":
        count[rid] = count.get(rid, 0) + 1
want = {"100212": "cron", "100214": "sudo", "100218": "find", "100300": "FIM honeypot_app"}
bad = 0
for rid, what in want.items():
    if rid in count:
        print(f"  \033[32m[OK]\033[0m   {rid} ({what}) x{count[rid]}")
    else:
        bad += 1
        print(f"  \033[31m[FAIL]\033[0m {rid} ({what}) absente")
others = {k: v for k, v in count.items() if k not in want}
if others:
    print(f"  autres règles vues : {others}")
sys.exit(1 if bad else 0)
PY
  if [[ $? -eq 0 ]]; then OKN=$((OKN+1)); else FAILN=$((FAILN+1)); fi
fi

# -----------------------------------------------------------------------------
sec "7. Dashboard Wazuh « Honeypot »"
PW="${WAZUH_ADMIN_PASSWORD:-}"
if [[ -z "$PW" && -f /root/wazuh-install-files.tar ]]; then
  PW=$(tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
       | grep -A1 "indexer_username: 'admin'" | grep -oP "indexer_password: '\K[^']+" || true)
fi
if [[ -z "$PW" ]]; then
  warn "mot de passe admin introuvable : vérification du dashboard sautée"
else
  for obj in dashboard/hp-dashboard visualization/hp-vis-per-honeypot visualization/hp-vis-top-commands index-pattern/hp-wazuh-alerts; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:$PW" "https://localhost/api/saved_objects/$obj")
    [[ "$code" == "200" ]] && ok "objet $obj présent" || fail "objet $obj absent (HTTP $code) -> sudo bash deploy/dashboard.sh"
  done
  n=$(curl -sk -u "admin:$PW" "https://localhost:9200/wazuh-alerts-*/_count?q=rule.groups:honeypot" | grep -oP '"count":\K[0-9]+' || echo 0)
  [[ "${n:-0}" -gt 0 ]] && ok "$n alertes honeypot indexées (visibles dans le dashboard)" \
    || warn "aucune alerte honeypot dans l'indexer (lancer --e2e ou tools/attack_demo.py)"
fi

echo -e "\n\e[1mRésultat:\e[0m \e[32m$OKN OK\e[0m, \e[33m$WARNN WARN\e[0m, \e[31m$FAILN FAIL\e[0m"
[[ $FAILN -eq 0 ]]
