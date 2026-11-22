#!/usr/bin/env bash
# =============================================================================
# test_nix01.sh — vérifie le déploiement de nix01.sh (honeypot + auditd + agent)
#
#   sudo bash tests/test_nix01.sh             # contrôles uniquement
#   sudo bash tests/test_nix01.sh --trigger   # + déclenche des actions privesc/FIM
#                                             #   à vérifier ensuite sur SRV01
# Env: MANAGER_IP (défaut 192.168.56.102)
# =============================================================================
set -uo pipefail

MANAGER_IP="${MANAGER_IP:-192.168.56.102}"
APPDIR="/home/nix01/honeypot_app"
ACCESS_LOG="$APPDIR/logs/access.log"
AGENT_CONF="/var/ossec/etc/ossec.conf"
RUNID="hptest-$(date +%s)"
OKN=0; FAILN=0; WARNN=0

ok()   { echo -e "  \e[32m[OK]\e[0m   $*"; OKN=$((OKN+1)); }
fail() { echo -e "  \e[31m[FAIL]\e[0m $*"; FAILN=$((FAILN+1)); }
warn() { echo -e "  \e[33m[WARN]\e[0m $*"; WARNN=$((WARNN+1)); }
sec()  { echo -e "\n\e[1m== $* ==\e[0m"; }
check(){ local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else fail "$msg"; fi; }

[[ $EUID -eq 0 ]] || { echo "Lancer en root: sudo bash $0"; exit 2; }

# -----------------------------------------------------------------------------
sec "1. Honeypot web (SweetBuzz)"
check "honeypot.service actif"            systemctl is-active --quiet honeypot.service
check "honeypot.service activé au boot"   systemctl is-enabled --quiet honeypot.service
check "port 5000 en écoute"               bash -c "ss -ltn | grep -q ':5000 '"
check "processus lancé en tant que nix01 (pas root)" \
      bash -c "ps -o user= -p \$(systemctl show -p MainPID --value honeypot.service) | grep -qx nix01"

code=$(curl -s -o /tmp/hp_home.html -w '%{http_code}' http://127.0.0.1:5000/ || echo 000)
[[ "$code" == "200" ]] && grep -q "SweetBuzz" /tmp/hp_home.html \
  && ok "GET / -> 200 + page SweetBuzz" || fail "GET / -> HTTP $code"

# -----------------------------------------------------------------------------
sec "2. Journalisation access.log"
check "access.log existe"                 test -f "$ACCESS_LOG"
check "access.log inscriptible par nix01" sudo -u nix01 test -w "$ACCESS_LOG"

before=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)
curl -s -o /dev/null -A "curl/8.5.0 $RUNID" -X DELETE http://127.0.0.1:5000/admin
sleep 1
line=$(grep -- "$RUNID" "$ACCESS_LOG" | tail -1)
if [[ -n "$line" ]]; then
  ok "requête de test journalisée"
  if [[ "$line" =~ ^HONEYPOT-ACCESS\ src=[^\ ]+\ method=DELETE\ path=/admin\ status=[0-9]+\ body=[^\ ]+\ ua=[^\ ]+\ xff=[^\ ]+$ ]]; then
    ok "format conforme au décodeur hp-access"
  else
    fail "format non conforme: $line"
  fi
else
  fail "requête de test absente de access.log (avant: $before lignes)"
fi
if [[ -s "$ACCESS_LOG.err" ]]; then
  fail "erreurs du hook: $(tail -2 "$ACCESS_LOG.err")"
else
  ok "pas d'erreur du hook (access.log.err vide)"
fi
curl -s -o /dev/null -A "curl/8.5.0 $RUNID-xff" -H "X-Forwarded-For: 6.6.6.6" http://127.0.0.1:5000/
sleep 1
grep -- "$RUNID-xff" "$ACCESS_LOG" | grep -q " src=6.6.6.6 " \
  && warn "IP source falsifiable via X-Forwarded-For" \
  || ok "IP source non falsifiable via X-Forwarded-For"

# -----------------------------------------------------------------------------
sec "2b. Honeypots SSH / FTP / Redis"
HPLOG=/var/log/honeypots
check "utilisateur système honeypot"      id honeypot
check "logrotate configuré"               test -f /etc/logrotate.d/honeypots
# probe = octets envoyés après connexion ; banner = début de réponse attendu
for spec in "ssh 2222 - SSH-2.0-OpenSSH" "ftp 21 QUIT\r\n 220" "redis 6379 PING\r\n +PONG"; do
  read -r hp port probe banner <<<"$spec"
  svc="honeypot-$hp.service"
  check "$svc actif"                      systemctl is-active --quiet "$svc"
  check "$svc activé au boot"             systemctl is-enabled --quiet "$svc"
  check "port $port en écoute ($hp)"      bash -c "ss -ltn | grep -q ':$port '"
  pid=$(systemctl show -p MainPID --value "$svc")
  if [[ -n "$pid" && "$pid" != 0 ]] && [[ "$(ps -o user= -p "$pid")" == "honeypot" ]]; then
    ok "$hp lancé en tant que honeypot (pas root)"
  else
    fail "$hp : processus absent ou pas lancé en honeypot (pid=$pid)"
  fi
  before=$(wc -l < "$HPLOG/$hp.json" 2>/dev/null || echo 0)
  got=$(timeout 6 python3 - "$port" "$probe" <<'PY' 2>/dev/null
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
if sys.argv[2] != "-":
    s.sendall(sys.argv[2].encode().decode("unicode_escape").encode())
time.sleep(0.5)
print(s.recv(200).decode("utf-8", "replace").splitlines()[0])
s.close()
PY
)
  [[ "$got" == "$banner"* ]] && ok "$hp répond (« ${got:0:40} »)" || fail "$hp : réponse inattendue « ${got:-rien} » (attendu $banner…)"
  sleep 1
  if python3 - "$HPLOG/$hp.json" "$before" "$hp" <<'PY'
import json, sys
path, before, hp = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lines = open(path).read().splitlines()[before:]
evs = [json.loads(l) for l in lines]
need = ("timestamp", "honeypot", "event_type", "srcip", "src_port", "session")
assert any(e["event_type"] == "connection" and e["srcip"] == "127.0.0.1" and e["honeypot"] == hp
           and all(k in e for k in need) for e in evs), evs
PY
  then ok "$hp.json : événement connection JSON valide (srcip, session...)"
  else fail "$hp.json : pas d'événement connection valide après la sonde"
  fi
done
ftp_pid=$(systemctl show -p MainPID --value honeypot-ftp.service)
if [[ -n "$ftp_pid" && "$ftp_pid" != 0 ]] && grep -qE "^CapAmb:\s*0*400$" "/proc/$ftp_pid/status"; then
  ok "FTP : seule capacité CAP_NET_BIND_SERVICE (port 21 sans root)"
else
  warn "FTP : capacités inattendues ($(grep CapAmb "/proc/$ftp_pid/status" 2>/dev/null))"
fi

# -----------------------------------------------------------------------------
sec "3. auditd (élévation de privilèges)"
check "auditd actif"                      systemctl is-active --quiet auditd
check "fichier de règles présent"         test -f /etc/audit/rules.d/honeypot-privesc.rules
loaded=$(auditctl -l 2>/dev/null)
for k in hp_identity hp_sudoers hp_cron hp_preload hp_exec hp_find hp_setuid hp_setgid hp_capset hp_ptrace hp_mount hp_module; do
  grep -Eq "(key=|-k )$k( |$)" <<<"$loaded" && ok "règle audit chargée: $k" || fail "règle audit manquante: $k"
done
grep -q "^enabled 2" < <(auditctl -s 2>/dev/null) && warn "auditd verrouillé (enabled 2) : reboot nécessaire pour modifier les règles"

# -----------------------------------------------------------------------------
sec "4. Agent Wazuh"
check "wazuh-agent actif"                 systemctl is-active --quiet wazuh-agent
check "wazuh-agent activé au boot"        systemctl is-enabled --quiet wazuh-agent
check "agent enrôlé (client.keys)"        test -s /var/ossec/etc/client.keys
state=$(grep -oP "status='\K[^']+" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null || echo "?")
[[ "$state" == "connected" ]] && ok "agent connecté au manager" || fail "état agent: $state"
grep -q "<address>$MANAGER_IP</address>" "$AGENT_CONF" \
  && ok "manager configuré: $MANAGER_IP" || fail "adresse manager != $MANAGER_IP dans ossec.conf"
check "manager joignable sur 1514/tcp"    timeout 3 bash -c "</dev/tcp/$MANAGER_IP/1514"
check "localfile access.log configuré"    grep -q "$ACCESS_LOG" "$AGENT_CONF"
check "localfile audit.log configuré"     grep -q "/var/log/audit/audit.log" "$AGENT_CONF"
check "localfile JSON honeypots configuré" grep -q "<location>/var/log/honeypots/\*.json</location>" "$AGENT_CONF"
check "FIM realtime sur honeypot_app"     grep -q "realtime=\"yes\"[^>]*>$APPDIR" "$AGENT_CONF"
grep -q "ERROR" <(tail -200 /var/ossec/logs/ossec.log 2>/dev/null) \
  && warn "erreurs récentes dans /var/ossec/logs/ossec.log: $(grep ERROR /var/ossec/logs/ossec.log | tail -1)" \
  || ok "pas d'erreur récente dans ossec.log de l'agent"

# -----------------------------------------------------------------------------
if [[ "${1:-}" == "--trigger" ]]; then
  sec "5. Déclenchement privesc / FIM (à vérifier sur SRV01)"
  (cd / && sudo -u nix01 find /tmp -maxdepth 0 >/dev/null 2>&1); ok "find lancé (hp_find -> 100218)"
  sudo -u nix01 sudo -n true >/dev/null 2>&1;                     ok "sudo lancé (hp_exec -> 100214)"
  touch /etc/cron.d/hp_selftest && rm -f /etc/cron.d/hp_selftest && ok "cron.d modifié (hp_cron -> 100212)"
  echo "$RUNID" > "$APPDIR/hp_selftest.txt"; sleep 3; rm -f "$APPDIR/hp_selftest.txt"
  ok "fichier créé/supprimé dans honeypot_app (FIM -> 100300)"
  echo -e "\n  -> Sur SRV01 : sudo bash tests/test_srv01.sh --since 10"
fi

echo -e "\n\e[1mRésultat:\e[0m \e[32m$OKN OK\e[0m, \e[33m$WARNN WARN\e[0m, \e[31m$FAILN FAIL\e[0m"
[[ $FAILN -eq 0 ]]
