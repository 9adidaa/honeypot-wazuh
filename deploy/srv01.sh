#!/usr/bin/env bash
# =============================================================================
# setup-srv01.sh — Wazuh Manager (SRV01) honeypot detection setup
#
# Deploys the custom decoder + detection rules for the SweetBuzz honeypot and
# privilege-escalation capture, enables alert archives, and restarts the manager.
#
# Idempotent: safe to re-run. Backs up existing files before overwriting.
#
# Usage:  sudo bash setup-srv01.sh
# =============================================================================
set -euo pipefail

WAZUH_ETC="/var/ossec/etc"
DECODER="$WAZUH_ETC/decoders/honeypot_decoders.xml"
RULES="$WAZUH_ETC/rules/honeypot_rules.xml"
OSSEC_CONF="$WAZUH_ETC/ossec.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"

log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
die()  { echo -e "\e[1;31m[x]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)"

command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1 \
  || die "Wazuh manager not found (no /var/ossec/bin/wazuh-control)."

# -----------------------------------------------------------------------------
# 1. Custom decoder — parses the HONEYPOT-ACCESS line into fields
# -----------------------------------------------------------------------------
log "Installing custom decoder -> $DECODER"
[[ -f "$DECODER" ]] && cp -a "$DECODER" "${DECODER}.bak.${STAMP}"
cat > "$DECODER" <<'XML'
<decoder name="hp-access">
  <prematch>HONEYPOT-ACCESS </prematch>
  <regex>src=(\S+) method=(\S+) path=(\S+) status=(\d+) body=(\S+) ua=(\S+)</regex>
  <order>hpsrc,hpmethod,hppath,hpstatus,hpbody,hpua</order>
</decoder>
XML

# -----------------------------------------------------------------------------
# 2. Detection rules — web attacks (100100-100199) + priv-esc (100200-100218)
#    + FIM (100300).  Child ordering matters: Wazuh stops at first match, and
#    level-0 children are evaluated before non-zero siblings, so the generic
#    404 rule is given level 3 and ID 100199 (evaluated after specific rules).
# -----------------------------------------------------------------------------
log "Installing detection rules -> $RULES"
[[ -f "$RULES" ]] && cp -a "$RULES" "${RULES}.bak.${STAMP}"
cat > "$RULES" <<'XML'
<!-- ============================================================
     SweetBuzz Honey Pot detection rules - web attacks + priv-esc
     All literal < > & in regexes are XML-escaped.
     ============================================================ -->
<group name="honeypot,web,">

  <rule id="100100" level="0">
    <decoded_as>hp-access</decoded_as>
    <description>SweetBuzz access log base event.</description>
  </rule>

  <rule id="100111" level="12">
    <if_sid>100100</if_sid>
    <field name="hpbody" type="pcre2">(?i)(admin'[+\s%]*--|'[+\s]*or[+\s]+'?1|'[+\s]*or[+\s]+1[+\s]*=[+\s]*1|'[+\s]*--|%27[+\s%]*--|%27[+\s]*or)</field>
    <description>SweetBuzz authentication bypass / SQL injection in login (SQLi)</description>
    <mitre><id>T1078</id></mitre>
    <group>attack,sqli,authentication_failed,</group>
  </rule>

  <rule id="100110" level="12">
    <if_sid>100100</if_sid>
    <field name="hpbody" type="pcre2">(?i)(union[+%\s]*select|select[+%0-9a-f\s]{1,8}from|or[+\s]*1[+\s]*=[+\s]*1|sleep\(|benchmark\(|information_schema|xp_cmdshell|%27|%22|--[+\s])</field>
    <description>SQL injection attempt against SweetBuzz (SQLi)</description>
    <mitre><id>T1190</id></mitre>
    <group>attack,sqli,</group>
  </rule>

  <rule id="100112" level="12">
    <if_sid>100100</if_sid>
    <field name="hpua" type="pcre2">(?i)(sqlmap|nikto|nmap|nessus|acunetix|havij|masscan|gobuster|dirb|wfuzz|hydra|burp)</field>
    <description>Known attack tool / scanner user-agent detected on SweetBuzz</description>
    <mitre><id>T1595</id></mitre>
    <group>attack,recon,scanner,</group>
  </rule>

  <rule id="100120" level="10">
    <if_sid>100100</if_sid>
    <field name="hpbody" type="pcre2">(?i)(script|onerror|javascript:|document\.cookie|%3c|svG/onload|img[+\s]src)</field>
    <description>XSS / HTML injection payload submitted to SweetBuzz</description>
    <mitre><id>T1059.007</id></mitre>
    <group>attack,xss,</group>
  </rule>

  <rule id="100130" level="12">
    <if_sid>100100</if_sid>
    <field name="hpmethod" type="pcre2">^DELETE$|^PUT$|^PATCH$</field>
    <description>HTTP method tampering / admin honeypot trap triggered on /admin</description>
    <mitre><id>T1190</id></mitre>
    <group>attack,method_tampering,</group>
  </rule>

  <rule id="100150" level="12">
    <if_sid>100100</if_sid>
    <field name="hpbody" type="pcre2">(?i)(;|\||`|\$\(|&amp;&amp;)[+\s]*(whoami|id|cat|ls|curl|wget|nc|bash|sh|python)</field>
    <description>Potential command injection payload on SweetBuzz</description>
    <mitre><id>T1059</id></mitre>
    <group>attack,command_injection,</group>
  </rule>

  <rule id="100140" level="6">
    <if_sid>100100</if_sid>
    <field name="hppath" type="pcre2">(?i)(\.env|\.git|wp-admin|phpmyadmin|\.aws|id_rsa|backup\.sql|\.bak|\.\./|%2e%2e)</field>
    <description>Honeypot probe for sensitive path/file</description>
    <mitre><id>T1595</id></mitre>
    <group>attack,recon,</group>
  </rule>

  <rule id="100199" level="3">
    <if_sid>100100</if_sid>
    <field name="hpstatus" type="pcre2">^404$</field>
    <description>SweetBuzz 404 (probing)</description>
  </rule>

  <rule id="100191" level="8" frequency="8" timeframe="120">
    <if_matched_sid>100199</if_matched_sid>
    <same_source_ip />
    <description>Directory/file brute force against SweetBuzz (many 404s)</description>
    <mitre><id>T1595</id></mitre>
    <group>attack,recon,web_scan,</group>
  </rule>

  <rule id="100101" level="3">
    <if_sid>100100</if_sid>
    <description>SweetBuzz HTTP request</description>
  </rule>

</group>

<!-- ===================== Privilege escalation ===================== -->
<group name="honeypot,linux,privilege_escalation,">

  <rule id="100200" level="3">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_</field>
    <description>Honeypot audit event (key match)</description>
  </rule>

  <rule id="100210" level="8">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_identity$</field>
    <description>Identity file modified (/etc/passwd|shadow|group|gshadow) - possible privesc backdoor</description>
    <mitre><id>T1136.001</id></mitre>
    <group>attack,privilege_escalation,persistence,</group>
  </rule>

  <rule id="100211" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_sudoers$</field>
    <description>Sudoers configuration modified - possible privilege escalation</description>
    <mitre><id>T1548.003</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100212" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_cron$</field>
    <description>Cron configuration modified - possible persistence/privesc</description>
    <mitre><id>T1053.003</id></mitre>
    <group>attack,privilege_escalation,persistence,</group>
  </rule>

  <rule id="100213" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_preload$</field>
    <description>ld.so.preload modified - LD_PRELOAD rootkit/privesc attempt</description>
    <mitre><id>T1574.006</id></mitre>
    <group>attack,privilege_escalation,rootkit,</group>
  </rule>

  <rule id="100214" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_exec$</field>
    <description>Privileged command executed (sudo/su/passwd/usermod/groupmod)</description>
    <mitre><id>T1548</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100215" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_setuid$|^hp_setgid$|^hp_capset$</field>
    <description>setuid/setgid/capability change by non-root - privesc indicator</description>
    <mitre><id>T1548.001</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100216" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_ptrace$</field>
    <description>ptrace by non-root user - process injection / privesc indicator</description>
    <mitre><id>T1055</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100217" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_mount$|^hp_module$</field>
    <description>Mount / kernel module operation by non-root - privesc indicator</description>
    <mitre><id>T1548.002</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100218" level="8">
    <if_sid>80700</if_sid>
    <field name="audit.key" type="pcre2">^hp_find$</field>
    <description>find executed - possible SUID enumeration / privesc recon</description>
    <mitre><id>T1083</id></mitre>
    <group>attack,privilege_escalation,recon,</group>
  </rule>

</group>

<!-- ================ FIM: honeypot app + sensitive files ================ -->
<group name="honeypot,linux,syscheck,">
  <rule id="100300" level="7">
    <if_sid>550,554</if_sid>
    <field name="file" type="pcre2">/home/nix01/honeypot_app</field>
    <description>SweetBuzz honeypot application files modified (FIM)</description>
    <mitre><id>T1565</id></mitre>
    <group>attack,web,integrity_monitoring,</group>
  </rule>
</group>
XML

# -----------------------------------------------------------------------------
# 3. Enable alert archives (logall) for debugging/troubleshooting
# -----------------------------------------------------------------------------
if ! grep -q "<logall>yes</logall>" "$OSSEC_CONF"; then
  log "Enabling logall (archives) in ossec.conf"
  cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.${STAMP}"
  # insert a global block with logall just before the first closing </ossec_config>
  python3 - "$OSSEC_CONF" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
block = "  <global><logall>yes</logall><logall_json>yes</logall_json></global>\n"
idx = s.rfind("</ossec_config>")
s = s[:idx] + block + s[idx:]
open(p, "w").write(s)
PY
else
  log "logall already enabled — skipping ossec.conf change"
fi

# -----------------------------------------------------------------------------
# 4. Restart the manager and wait until analysisd has fully loaded the rules
# -----------------------------------------------------------------------------
log "Restarting Wazuh manager"
/var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true

# Wait (up to ~90s) for analysisd to come up and report a fresh rule-load line.
log "Waiting for analysisd to finish loading rules..."
for _ in $(seq 1 45); do
  if pgrep -f wazuh-analysisd >/dev/null 2>&1 && \
     grep -qE "Total rules enabled" /var/ossec/logs/ossec.log 2>/dev/null; then
    sleep 3   # allow analysisd to finish initialising after the load line
    break
  fi
  sleep 2
done

# -----------------------------------------------------------------------------
# 5. Smoke test the decoder + a representative detection rule
# -----------------------------------------------------------------------------
log "Decoder/rule smoke test:"
SMOKE_IN="$(mktemp)"
printf "HONEYPOT-ACCESS src=1.2.3.4 method=DELETE path=/admin status=200 body=- ua=curl\n" > "$SMOKE_IN"
smoke_out=$(/var/ossec/bin/wazuh-logtest -v < "$SMOKE_IN" 2>&1 || true)
rm -f "$SMOKE_IN"

smoke_ok=1
grep -q "name: 'hp-access'" <<<"$smoke_out" || smoke_ok=0
grep -q "id: '100130'" <<<"$smoke_out" || grep -q "Rule 100130 matched" <<<"$smoke_out" || smoke_ok=0
if [[ $smoke_ok -eq 1 ]]; then
  log "  decoder hp-access: OK"
  log "  rule 100130 (method tampering): OK"
else
  warn "Smoke test incomplete — re-run wazuh-logtest manually to inspect (analysisd may still be starting)."
fi

enabled=$(grep -E "Total rules enabled" /var/ossec/logs/ossec.log 2>/dev/null | tail -1 | sed -E "s/.*'([0-9]+)'.*/\1/" || echo "?")
log "Done. Total rules enabled: ${enabled}"
log "Custom rules file: $RULES"
log "Fire attacks from NIX01 (or host) and watch:"
echo "    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep honeypot"
