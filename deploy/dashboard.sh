#!/usr/bin/env bash
# =============================================================================
# dashboard.sh — importe le tableau de bord "Honeypot" dans le Wazuh dashboard
#
#   POST https://localhost/api/saved_objects/_import?overwrite=true
#   (fichier wazuh/dashboard/honeypot-dashboard.ndjson, généré par tools/build_dashboard.py)
#
# Mot de passe admin : $WAZUH_ADMIN_PASSWORD, sinon lu dans /root/wazuh-install-files.tar
# Appelé par deploy/srv01.sh. Idempotent (overwrite=true).
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDJSON="$REPO_DIR/wazuh/dashboard/honeypot-dashboard.ndjson"
URL="${DASHBOARD_URL:-https://localhost}"
USER_="${WAZUH_ADMIN_USER:-admin}"

log()  { echo -e "\e[1;32m[+]\e[0m [dashboard] $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m [dashboard] $*"; }
die()  { echo -e "\e[1;31m[x]\e[0m [dashboard] $*" >&2; exit 1; }

[[ -f "$NDJSON" ]] || die "fichier absent : $NDJSON"

PW="${WAZUH_ADMIN_PASSWORD:-}"
if [[ -z "$PW" && -f /root/wazuh-install-files.tar ]]; then
  PW=$(tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
       | grep -A1 "indexer_username: '$USER_'" | grep -oP "indexer_password: '\K[^']+" || true)
fi
[[ -n "$PW" ]] || die "mot de passe $USER_ introuvable (exporter WAZUH_ADMIN_PASSWORD)"

log "Attente du Wazuh dashboard ($URL)..."
for i in $(seq 1 60); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$USER_:$PW" "$URL/api/status" || true)
  [[ "$code" == "200" ]] && break
  [[ $i -eq 60 ]] && die "dashboard injoignable (HTTP $code après 5 min)"
  sleep 5
done

log "Import de $(wc -l < "$NDJSON") objets (index pattern, visualisations, dashboard)"
resp=$(curl -sk -u "$USER_:$PW" -H "osd-xsrf: true" \
       -X POST "$URL/api/saved_objects/_import?overwrite=true" \
       --form "file=@$NDJSON")
if grep -q '"success":true' <<<"$resp"; then
  log "Dashboard importé : $URL/app/dashboards#/view/hp-dashboard"
else
  die "import échoué : ${resp:0:600}"
fi
