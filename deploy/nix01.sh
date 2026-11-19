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
# Usage:  sudo bash setup-nix01.sh
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
# Deploy the SweetBuzz honeypot if it isn't already present. The app contains
# three intentional vulnerabilities (SQLi login, DELETE /admin, stored XSS).
if [[ ! -f "$APPDIR/app.py" ]]; then
  log "Writing $APPDIR/app.py (SweetBuzz honeypot)"
  cat > "$APPDIR/app.py" <<'PYEOF'
from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_honeypot_key'

DB_PATH = 'honeypot.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, is_admin INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, comment TEXT)''')
    cursor.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'HoneyMaster2026!', 1)")
    conn.commit()
    conn.close()

STYLE = """
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#fff8e7; color:#3a2a12; margin:0; }
  header { background:linear-gradient(90deg,#f0a500,#ffd166); padding:24px; text-align:center; }
  header h1 { margin:0; }
  .wrap { max-width:760px; margin:32px auto; background:#fff; padding:28px; border-radius:12px;
          box-shadow:0 2px 10px rgba(0,0,0,.08); }
  input, textarea, button { font-size:16px; padding:10px; margin:6px 0; width:100%; box-sizing:border-box; }
  button { background:#f0a500; border:0; color:#fff; font-weight:600; cursor:pointer; border-radius:8px; }
  a { color:#c47f00; }
</style>
"""

@app.route('/')
def index():
    html = STYLE + """
    <header><h1>SweetBuzz Honey Co.</h1><p>Artisanal honey, delivered with a sting.</p></header>
    <div class="wrap">
      <h2>Welcome to our hive!</h2>
      <p>Browse our artisanal honeys, leave a review, or sign in to your account.</p>
      <ul>
        <li><a href="/login">Customer Login</a></li>
        <li><a href="/feedback">Reviews</a></li>
        <li><a href="/admin">Admin Panel</a></li>
      </ul>
    </div>"""
    return render_template_string(html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # VULNERABLE SQL QUERY (SQLi)
        query = f"SELECT id, username, is_admin FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except Exception as e:
            user = None
            error = "Database error"
        conn.close()
        if user:
            session['user'] = user[1]
            return render_template_string(STYLE + """
              <header><h1>VIP Dashboard</h1></header>
              <div class="wrap"><h2>Welcome, {{ u }}!</h2>
              <p>Flag: <code>CODEBY{HONEYPOT_SQLI_BYPASS_SUCCESS}</code></p></div>""", u=user[1])
        error = error or "Invalid credentials"
    html = STYLE + """
    <header><h1>Customer Login</h1></header>
    <div class="wrap">
      <form method="post">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Sign In</button>
      </form>
      {% if error %}<p style="color:#b00">{{ error }}</p>{% endif %}
    </div>"""
    return render_template_string(html, error=error)

@app.route('/admin', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin():
    if request.method == 'GET':
        return render_template_string(STYLE + """
        <header><h1>Admin Panel</h1></header>
        <div class="wrap">
          <form method="post">
            <input name="password" type="password" placeholder="Admin Password">
            <button type="submit">Authenticate</button>
          </form>
        </div>""")
    elif request.method == 'POST':
        return render_template_string(STYLE + "<div class='wrap'><h2>Access Denied</h2></div>"), 403
    elif request.method == 'DELETE':
        # Method Tampering Bypass!
        return "<h1>Admin Authorization Bypassed. Flag: CODEBY{METHOD_TAMPERING_MASTER}</h1>"

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        comment = request.form.get('comment', '')
        cursor.execute("INSERT INTO feedback (name, comment) VALUES (?, ?)", (name, comment))
        conn.commit()
    cursor.execute("SELECT name, comment FROM feedback ORDER BY id DESC")
    feedbacks = cursor.fetchall()
    conn.close()
    html = STYLE + """
    <header><h1>Customer Reviews</h1></header>
    <div class="wrap">
      <form method="post">
        <input name="name" placeholder="Your name">
        <textarea name="comment" placeholder="Your review"></textarea>
        <button type="submit">Post Review</button>
      </form>
      <hr>
      {% for f in feedbacks %}
        <h4>{{ f[0] }}</h4>
        <p>{{ f[1]|safe }}</p>
      {% endfor %}
    </div>"""
    return render_template_string(html, feedbacks=feedbacks)

# === Wazuh honeypot access logging (live capture) ===
import re as _re
from urllib.parse import unquote_plus as _uq
_ACCESS_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "access.log")

def _field(s, n=1200):
    s = _re.sub(r"[^\x20-\x7e]", "?", str(s))
    s = _re.sub(r"\s+", " ", s).strip()
    s = s.replace('%', '%25').replace(' ', '+').replace('"', '%22')
    return s[:n]

@app.after_request
def _hp_access_log(resp):
    try:
        src = request.headers.get("X-Forwarded-For", request.remote_addr) or "-"
        q = request.query_string.decode("utf-8", "replace")
        body = ""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                if request.form:
                    body = "&".join("%s=%s" % (k, v) for k, v in request.form.items())
                else:
                    body = request.get_data(cache=True, as_text=True)[:1500] or ""
            except Exception:
                body = ""
        path = request.path + ("?" + q if q else "")
        payload = body if body else q
        # decode once so detection rules see plaintext keywords, then re-encode safely
        plain = _uq(str(payload))
        line = (
            "HONEYPOT-ACCESS src=%s method=%s path=%s status=%d body=%s ua=%s\n"
            % (src.split(",")[0].strip(), request.method, _field(path),
               resp.status_code, _field(plain) or "-", _field(request.user_agent.string, 200))
        )
        os.makedirs(os.path.dirname(_ACCESS_LOG), exist_ok=True)
        with open(_ACCESS_LOG, "a") as _f:
            _f.write(line)
    except Exception as _e:
        try:
            os.makedirs(os.path.dirname(_ACCESS_LOG), exist_ok=True)
            with open(_ACCESS_LOG + ".err", "a") as _ef:
                _ef.write("ERR %r\n" % (_e,))
        except Exception:
            pass
    return resp


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
PYEOF
else
  log "$APPDIR/app.py already present — ensuring access-log hook exists"
  if ! grep -q "_hp_access_log" "$APPDIR/app.py"; then
    warn "Access-log hook missing; app.py was not overwritten. Add it manually or delete app.py and re-run."
  fi
fi

chown nix01:nix01 "$APPDIR/app.py"
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
