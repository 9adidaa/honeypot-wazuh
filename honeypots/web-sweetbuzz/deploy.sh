#!/bin/bash
# Standalone install of SweetBuzz on a host (the lab uses deploy/nix01.sh instead).
# Run from this directory: sudo bash deploy.sh
set -euo pipefail
cd "$(dirname "$0")"
echo "Setting up Honey Pot Web App..."
apt-get update -qq && apt-get install -y -qq python3 python3-venv openssl
id nix01 >/dev/null 2>&1 || useradd -m -s /bin/bash nix01
APPDIR=/home/nix01/honeypot_app
mkdir -p "$APPDIR/logs" /etc/honeypots
install -m 644 app.py requirements.txt "$APPDIR/"
chown -R nix01:nix01 "$APPDIR"
[[ -s /etc/honeypots/sweetbuzz.env ]] || printf 'HP_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > /etc/honeypots/sweetbuzz.env
chown root:nix01 /etc/honeypots/sweetbuzz.env; chmod 640 /etc/honeypots/sweetbuzz.env
[[ -x "$APPDIR/venv/bin/python" ]] || sudo -u nix01 python3 -m venv "$APPDIR/venv"
sudo -u nix01 "$APPDIR/venv/bin/pip" install -q -r "$APPDIR/requirements.txt"
install -m 644 honeypot.service /etc/systemd/system/honeypot.service
systemctl daemon-reload
systemctl enable --now honeypot
systemctl restart honeypot
echo "Honey Pot App deployed and running on port 5000!"
