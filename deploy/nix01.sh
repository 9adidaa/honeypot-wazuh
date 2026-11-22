#!/usr/bin/env bash
# =============================================================================
# setup-nix01.sh — SweetBuzz honeypot host (NIX01) capture setup
#
# Prepares NIX01 to feed web-attack and privilege-escalation activity to the
# Wazuh manager (SRV01) at 192.168.56.102:
#   1. Fixes DNS + kills stuck unattended-upgrade (if present)
#   2. Installs the SweetBuzz Flask honeypot (app.py + venv + systemd service)
#   3. Adds an @app.after_request access-log hook -> logs/access.log
#   4. Installs auditd + custom privesc audit rules
#   5. Installs the Wazuh agent, enrolls it, and adds localfiles/FIM/rootcheck/SCA
#
# Idempotent: safe to re-run. Backs up existing files before overwriting.
#
# Usage:  sudo bash deploy/nix01.sh   (from a checkout of the repository)
# Env:    MANAGER_IP (default 192.168.56.102), AGENT_NAME (default NIX01)
# =============================================================================
set -euo pipefail

MANAGER_IP="${MANAGER_IP:-192.168.56.102}"
AGENT_NAME="${AGENT_NAME:-NIX01}"
WAZUH_VER="4.14.9-1"
HOMEDIR="/home/nix01"
APPDIR="$HOMEDIR/honeypot_app"
ACCESS_LOG="$APPDIR/logs/access.log"
AUDIT_RULES="/etc/audit/rules.d/honeypot-privesc.rules"
AGENT_CONF="/var/ossec/etc/ossec.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
die()  { echo -e "\e[1;31m[x]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"

# -----------------------------------------------------------------------------
# 0. DNS + stuck package locks
# -----------------------------------------------------------------------------
log "Ensuring DNS resolution"
grep -q "8.8.8.8" /etc/resolv.conf 2>/dev/null || {
  echo "nameserver 8.8.8.8"  | tee /etc/resolv.conf >/dev/null
  echo "nameserver 1.1.1.1"  | tee -a /etc/resolv.conf >/dev/null
}

if pgrep -f "unattended-upgrade" >/dev/null 2>&1; then
  warn "Killing stuck unattended-upgrade holding the dpkg lock"
  pkill -f "unattended-upgrade" || true
  sleep 2
fi

export DEBIAN_FRONTEND=noninteractive
log "Updating apt index"
apt-get update -qq || warn "apt update had errors (continuing)"

# -----------------------------------------------------------------------------
# 1. Base packages + SweetBuzz app
# -----------------------------------------------------------------------------
log "Installing base packages (python3, venv, curl)"
apt-get install -y -qq python3 python3-pip python3-venv curl openssl >/dev/null

mkdir -p "$APPDIR/logs"
chown -R nix01:nix01 "$APPDIR" 2>/dev/null || true

# --- app.py -----------------------------------------------------------------
# Single source of truth: honeypots/web-sweetbuzz/app.py from this repository
# (/opt/honeypot-wazuh when provisioned by Vagrant). The app contains three
# intentional vulnerabilities (SQLi login, DELETE /admin, stored XSS).
APP_SRC="$REPO_DIR/honeypots/web-sweetbuzz/app.py"
[[ -f "$APP_SRC" ]] || die "app.py introuvable: $APP_SRC"
if ! cmp -s "$APP_SRC" "$APPDIR/app.py"; then
  [[ -f "$APPDIR/app.py" ]] && cp -a "$APPDIR/app.py" "$APPDIR/app.py.bak.${STAMP}"
  log "Installing $APPDIR/app.py from $APP_SRC"
  install -m 644 -o nix01 -g nix01 "$APP_SRC" "$APPDIR/app.py"
else
  log "$APPDIR/app.py already up to date"
fi

mkdir -p "$APPDIR/logs"
: >> "$ACCESS_LOG"
chown -R nix01:nix01 "$APPDIR/logs"

# --- venv + requirements ----------------------------------------------------
if [[ ! -x "$APPDIR/venv/bin/python" ]]; then
  log "Creating virtualenv and installing Flask"
  sudo -u nix01 python3 -m venv "$APPDIR/venv"
fi
sudo -u nix01 "$APPDIR/venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
echo "flask==3.0.2" > "$APPDIR/requirements.txt"
sudo -u nix01 "$APPDIR/venv/bin/pip" install -q -r "$APPDIR/requirements.txt"

# --- systemd service --------------------------------------------------------
log "Installing honeypot.service"
cat > /etc/systemd/system/honeypot.service <<'UNIT'
[Unit]
Description=SweetBuzz Honey Pot Web App
After=network.target

[Service]
User=nix01
WorkingDirectory=/home/nix01/honeypot_app
ExecStart=/home/nix01/honeypot_app/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now honeypot.service
systemctl restart honeypot.service

# -----------------------------------------------------------------------------
# 2. auditd + custom privilege-escalation rules
# -----------------------------------------------------------------------------
log "Installing auditd + privesc rules"
apt-get install -y -qq auditd audispd-plugins >/dev/null

cat > "$AUDIT_RULES" <<'AUDIT'
## Wazuh honeypot - privilege escalation audit rules (NIX01)
-D
-b 8192
-w /etc/passwd -p wa -k hp_identity
-w /etc/shadow -p wa -k hp_identity
-w /etc/group -p wa -k hp_identity
-w /etc/gshadow -p wa -k hp_identity
-w /etc/sudoers -p wa -k hp_sudoers
-w /etc/sudoers.d -p wa -k hp_sudoers
-w /var/spool/cron -p wa -k hp_cron
-w /etc/crontab -p wa -k hp_cron
-w /etc/cron.d -p wa -k hp_cron
-w /etc/ld.so.preload -p wa -k hp_preload
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/sudo -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/su -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/passwd -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/useradd -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/usermod -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/groupadd -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/groupmod -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/chsh -k hp_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/find -k hp_find
-a always,exit -F arch=b64 -S setuid -F euid!=0 -k hp_setuid
-a always,exit -F arch=b64 -S setgid -F euid!=0 -k hp_setgid
-a always,exit -F arch=b64 -S capset -F euid!=0 -k hp_capset
-a always,exit -F arch=b64 -S ptrace -F euid!=0 -k hp_ptrace
-a always,exit -F arch=b64 -S mount -F euid!=0 -k hp_mount
-a always,exit -F arch=b64 -S delete_module -k hp_module
AUDIT
systemctl enable --now auditd
augenrules --load >/dev/null 2>&1 || warn "augenrules --load reported issues"
auditctl -l | grep -c hp_ >/dev/null && log "audit rules loaded: $(auditctl -l | wc -l)"

# -----------------------------------------------------------------------------
# 3. Wazuh agent install
# -----------------------------------------------------------------------------
if [[ ! -x /var/ossec/bin/wazuh-agentd ]]; then
  log "Adding Wazuh apt repository (4.x)"
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  log "Installing wazuh-agent ${WAZUH_VER}"
  apt-get install -y -qq "wazuh-agent=${WAZUH_VER}" || apt-get install -y -qq wazuh-agent
fi

# -----------------------------------------------------------------------------
# 4. Agent configuration: server + localfiles + FIM + rootcheck + SCA
# -----------------------------------------------------------------------------
log "Configuring agent server address -> $MANAGER_IP"
if grep -q "<address>" "$AGENT_CONF"; then
  sed -i -E "s#<address>[^<]*</address>#<address>${MANAGER_IP}</address>#" "$AGENT_CONF"
fi

# Append the honeypot capture block only once (dedupe on the marker comment).
if ! grep -q "HONEYPOT CAPTURE" "$AGENT_CONF"; then
  log "Appending honeypot localfile/FIM/rootcheck/SCA block"
  cp -a "$AGENT_CONF" "${AGENT_CONF}.bak.${STAMP}"
  # insert before the final </ossec_config> if present, else append
  python3 - "$AGENT_CONF" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
block = r'''
  <!-- ===== HONEYPOT CAPTURE (SweetBuzz web + priv-esc) ===== -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/home/nix01/honeypot_app/logs/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <syscheck>
    <disabled>no</disabled>
    <frequency>60</frequency>
    <directories check_all="yes" realtime="yes" report_changes="yes">/home/nix01/honeypot_app</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/group,/etc/sudoers,/etc/sudoers.d,/etc/crontab,/etc/cron.d,/root/.ssh,/home/nix01/.ssh</directories>
    <directories check_all="yes">/usr/bin,/usr/sbin</directories>
    <ignore type="sregex">honeypot.db$|logs/access.log$|\.pyc$</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
  </rootcheck>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>
'''
idx = s.rfind("</ossec_config>")
if idx == -1:
    s = s + "\n<ossec_config>\n" + block + "\n</ossec_config>\n"
else:
    s = s[:idx] + block + "\n" + s[idx:]
open(p, "w").write(s)
PY
else
  log "Honeypot block already present in ossec.conf — skipping"
fi

# -----------------------------------------------------------------------------
# 5. Enroll agent with the manager (only if not already enrolled)
# -----------------------------------------------------------------------------
if [[ ! -f /var/ossec/etc/client.keys ]]; then
  log "Enrolling agent '$AGENT_NAME' with manager $MANAGER_IP"
  /var/ossec/bin/agent-auth -m "$MANAGER_IP" -A "$AGENT_NAME" || \
    warn "agent-auth failed — is the manager reachable on 1515/tcp?"
fi

log "Starting/enabling wazuh-agent"
systemctl enable --now wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent

sleep 5
log "Agent status: $(systemctl is-active wazuh-agent)"
log "Done. Verify the agent is Active on the manager:"
echo "    ssh srv01@$MANAGER_IP  'sudo /var/ossec/bin/agent_control -l'"
log "Honeypot app: http://$(hostname -I | awk '{print $1}'):5000/"
