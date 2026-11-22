#!/usr/bin/env bash
# =============================================================================
# honeypots.sh — déploie les honeypots "from scratch" (SSH, FTP, Redis) sur NIX01
#
#   - utilisateur système non privilégié `honeypot`
#   - code dans /opt/honeypots (+ venv pour paramiko), un service systemd chacun
#   - logs JSON lines dans /var/log/honeypots/<nom>.json (+ logrotate)
#   - bloc <localfile> JSON dans l'ossec.conf de l'agent Wazuh (une seule fois)
#
# Appelé par deploy/nix01.sh. Idempotent : relançable sans dégâts.
# Usage : sudo bash deploy/honeypots.sh
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_DIR/honeypots"
OPT="/opt/honeypots"
LOGDIR="/var/log/honeypots"
DATADIR="/var/lib/honeypots"
AGENT_CONF="/var/ossec/etc/ossec.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
HONEYPOTS=(ssh ftp redis)

log()  { echo -e "\e[1;32m[+]\e[0m [honeypots] $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m [honeypots] $*"; }
die()  { echo -e "\e[1;31m[x]\e[0m [honeypots] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"

# --- utilisateur + répertoires ------------------------------------------------
if ! id honeypot >/dev/null 2>&1; then
  log "Création de l'utilisateur système honeypot"
  useradd --system --no-create-home --home-dir "$DATADIR" --shell /usr/sbin/nologin honeypot
fi
install -d -m 755 -o root -g root "$OPT"
install -d -m 750 -o honeypot -g honeypot "$LOGDIR" "$DATADIR"

# --- venv (paramiko = transport SSH uniquement) -------------------------------
export DEBIAN_FRONTEND=noninteractive
command -v python3 >/dev/null && python3 -c "import venv, ensurepip" 2>/dev/null \
  || apt-get install -y -qq python3 python3-venv >/dev/null
if [[ ! -x "$OPT/venv/bin/python" ]]; then
  log "Création du venv $OPT/venv"
  python3 -m venv "$OPT/venv"
fi
install -m 644 "$SRC/requirements.txt" "$OPT/requirements.txt"
"$OPT/venv/bin/pip" install -q --disable-pip-version-check -r "$OPT/requirements.txt"

# --- code + services ------------------------------------------------------------
install -m 644 "$SRC/common/hplog.py" "$OPT/hplog.py"
for hp in "${HONEYPOTS[@]}"; do
  py="$SRC/$hp/${hp}_honeypot.py"
  unit="$SRC/$hp/honeypot-$hp.service"
  if [[ ! -f "$py" || ! -f "$unit" ]]; then
    warn "$hp : fichiers absents ($py / $unit) — ignoré"
    continue
  fi
  log "Installation du honeypot $hp"
  install -m 644 "$py" "$OPT/${hp}_honeypot.py"
  install -m 644 "$unit" "/etc/systemd/system/honeypot-$hp.service"
  touch "$LOGDIR/$hp.json"; chown honeypot:honeypot "$LOGDIR/$hp.json"; chmod 640 "$LOGDIR/$hp.json"
done
systemctl daemon-reload
for hp in "${HONEYPOTS[@]}"; do
  [[ -f "/etc/systemd/system/honeypot-$hp.service" ]] || continue
  systemctl enable "honeypot-$hp.service" >/dev/null 2>&1
  systemctl restart "honeypot-$hp.service"
done

# --- rotation des logs (copytruncate : l'agent Wazuh garde son descripteur) ----
cat > /etc/logrotate.d/honeypots <<'ROT'
/var/log/honeypots/*.json {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
ROT

# --- agent Wazuh : collecte JSON ------------------------------------------------
if [[ -f "$AGENT_CONF" ]]; then
  if ! grep -q "HONEYPOT JSON LOGS" "$AGENT_CONF"; then
    log "Ajout du <localfile> JSON /var/log/honeypots/*.json dans $AGENT_CONF"
    cp -a "$AGENT_CONF" "${AGENT_CONF}.bak.${STAMP}"
    python3 - "$AGENT_CONF" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
block = '''
  <!-- ===== HONEYPOT JSON LOGS (SSH / FTP / Redis) ===== -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/honeypots/*.json</location>
  </localfile>
'''
idx = s.rfind("</ossec_config>")
s = s + "\n<ossec_config>\n" + block + "</ossec_config>\n" if idx == -1 else s[:idx] + block + "\n" + s[idx:]
open(p, "w").write(s)
PY
  else
    log "Bloc HONEYPOT JSON LOGS déjà présent — inchangé"
  fi
else
  warn "agent Wazuh absent ($AGENT_CONF) — collecte JSON non configurée"
fi

sleep 2
for hp in "${HONEYPOTS[@]}"; do
  [[ -f "/etc/systemd/system/honeypot-$hp.service" ]] || continue
  log "honeypot-$hp : $(systemctl is-active "honeypot-$hp.service")"
done
