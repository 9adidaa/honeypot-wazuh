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
