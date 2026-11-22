#!/usr/bin/env bash
# =============================================================================
# demo_reset.sh — remet le lab à zéro entre deux prises de la vidéo de démo.
#
# Vide les journaux des honeypots (NIX01) et les alertes Wazuh (SRV01) pour que
# le `tail -f` et `show_alerts.py --since` repartent propres. N'EFFACE PAS les
# données déjà indexées : sur le dashboard, utiliser simplement la plage de temps
# "Last 15 minutes" (voir docs/DEMO.md) pour ne montrer que l'attaque filmée.
#
# Usage (depuis le PC hôte, à la racine du dépôt) :
#   bash scripts/demo_reset.sh            # vide NIX01 + SRV01 via vagrant ssh
#   bash scripts/demo_reset.sh --on-vm    # à lancer AVEC sudo, directement sur une VM
#
# Idempotent, sans danger : ne touche qu'aux fichiers de logs.
# =============================================================================
set -uo pipefail

reset_nix01() {
  # journaux JSON des honeypots SSH/FTP/Redis + fichiers déposés par FTP
  truncate -s 0 /var/log/honeypots/*.json 2>/dev/null || true
  rm -f /var/lib/honeypots/ftp_uploads/* 2>/dev/null || true
  # journal d'accès du honeypot web
  truncate -s 0 /home/nix01/honeypot_app/logs/access.log 2>/dev/null || true
  : > /home/nix01/honeypot_app/logs/access.log.err 2>/dev/null || true
  echo "[nix01] journaux honeypots + access.log vidés"
}

reset_srv01() {
  # alertes Wazuh (fichiers lus par tail -f et show_alerts.py)
  truncate -s 0 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
  truncate -s 0 /var/ossec/logs/alerts/alerts.log 2>/dev/null || true
  truncate -s 0 /var/ossec/logs/archives/archives.json 2>/dev/null || true
  truncate -s 0 /var/ossec/logs/archives/archives.log 2>/dev/null || true
  echo "[srv01] alertes/archives Wazuh vidées"
}

if [[ "${1:-}" == "--on-vm" ]]; then
  [[ $EUID -eq 0 ]] || { echo "Lancer en root: sudo bash $0 --on-vm"; exit 2; }
  if [[ -d /var/log/honeypots ]]; then reset_nix01; fi
  if [[ -d /var/ossec/logs/alerts ]]; then reset_srv01; fi
  exit 0
fi

# Depuis l'hôte : on pilote les deux VM avec vagrant.
command -v vagrant >/dev/null || { echo "vagrant introuvable — lancer avec --on-vm sur chaque VM"; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

echo "== Reset de la démo =="
vagrant ssh nix01 -c "sudo truncate -s 0 /var/log/honeypots/*.json; sudo rm -f /var/lib/honeypots/ftp_uploads/*; sudo truncate -s 0 /home/nix01/honeypot_app/logs/access.log; echo '[nix01] journaux vidés'" 2>/dev/null
vagrant ssh srv01 -c "sudo truncate -s 0 /var/ossec/logs/alerts/alerts.json /var/ossec/logs/alerts/alerts.log; sudo truncate -s 0 /var/ossec/logs/archives/archives.json /var/ossec/logs/archives/archives.log 2>/dev/null; echo '[srv01] alertes vidées'" 2>/dev/null

echo "Prêt pour une nouvelle prise. Sur le dashboard : plage de temps = Last 15 minutes."
