#!/usr/bin/env python3
"""
ssh_honeypot.py — honeypot SSH (port 2222) écrit pour le projet.

paramiko ne sert que de transport SSH (chiffrement, échange de clés) ; la logique
d'authentification et le faux shell interactif sont les nôtres.

Journalise (JSON lines, /var/log/honeypots/ssh.json) :
  connection, login_attempt (password / publickey), login_success,
  command (+ url pour wget/curl), session_closed

Env : HP_SSH_PORT (2222), HP_SSH_BIND (0.0.0.0), HP_SSH_ACCEPT (user:pass,...),
      HP_SSH_HOSTNAME (srv-db01), HP_LOG_DIR, HP_DATA_DIR
"""
import os
import re
import shlex
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "common")]
import paramiko  # noqa: E402
from hplog import DATA_DIR, HoneypotLogger, new_session  # noqa: E402

PORT = int(os.environ.get("HP_SSH_PORT", "2222"))
BIND = os.environ.get("HP_SSH_BIND", "0.0.0.0")
HOSTNAME = os.environ.get("HP_SSH_HOSTNAME", "srv-db01")
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
ACCEPT = {tuple(c.split(":", 1)) for c in os.environ.get(
    "HP_SSH_ACCEPT",
    "root:root,root:123456,root:password,root:toor,admin:admin,ubuntu:ubuntu,pi:raspberry,test:test",
).split(",") if ":" in c}
MAX_CLIENTS = 64
IDLE_TIMEOUT = 300
URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"|;&]+")

LOG = HoneypotLogger("ssh")

# --------------------------------------------------------------------------- faux système
FS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "srv", "tmp", "usr", "var"],
    "/root": [".bash_history", ".bashrc", ".ssh", "backup.sql", "notes.txt"],
    "/home": ["ubuntu", "admin"],
    "/home/ubuntu": [".bashrc", ".profile"],
    "/home/admin": [".bashrc", "deploy.sh"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "ssh", "crontab", "mysql", "os-release"],
    "/tmp": [],
    "/var": ["backups", "log", "www"],
    "/var/www": ["html"],
    "/opt": ["app"],
}
FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false\n"
                   "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nadmin:x:1001:1001::/home/admin:/bin/bash\n",
    "/etc/shadow": "root:$6$Vq3h0Zr1$Qm0vV2uE3kQ1oQb6m8Y0f1oQd2b3sS9mJ1u7cX0e8nL1a2:19700:0:99999:7:::\n"
                   "ubuntu:$6$Xk2l9Pq0$7H1c0bQ2d3e4f5g6h7i8j9k0lMnOpQrStUvWxYz1234:19700:0:99999:7:::\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {HOSTNAME}\n10.10.20.15 db-replica\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n',
    "/root/notes.txt": "TODO: rotate mysql root password (currently in /root/backup.sql)\n",
    "/root/backup.sql": "-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99');\n",
    "/home/admin/deploy.sh": "#!/bin/bash\nscp build.tgz deploy@10.10.20.30:/opt/app\n",
}
UNAME_A = f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"


class FakeShell:
    def __init__(self, user):
        self.user = user
        self.home = "/root" if user == "root" else f"/home/{user}"
        FS.setdefault(self.home, [".bashrc"])
        self.cwd = self.home

    def prompt(self):
        cwd = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{HOSTNAME}:{cwd}{'#' if self.user == 'root' else '$'} "

    def _path(self, p):
        if not p or p == "~":
            return self.home
        if p.startswith("~/"):
            p = self.home + p[1:]
        if not p.startswith("/"):
            p = self.cwd.rstrip("/") + "/" + p
        parts = []
        for part in p.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                parts and parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts)

    def run(self, line):
        """Exécute une ligne (peut contenir ; && || |). Retourne (sortie, exit?)."""
        out = []
        for part in re.split(r"\s*(?:;|&&|\|\||\|)\s*", line.strip()):
            if not part:
                continue
            res = self.run_one(part)
            if res is None:
                return "\r\n".join(out), True
            if res:
                out.append(res)
        return "\r\n".join(out), False

    def run_one(self, cmdline):
        try:
            argv = shlex.split(cmdline)
        except ValueError:
            argv = cmdline.split()
        if not argv:
            return ""
        while argv and (argv[0] in ("sudo", "nohup", "time") or "=" in argv[0]):
            argv = argv[1:]
        if not argv:
            return ""
        cmd, args = os.path.basename(argv[0]), argv[1:]
        if cmd in ("exit", "logout", "quit"):
            return None
        if cmd == "whoami":
            return self.user
        if cmd == "id":
            return ("uid=0(root) gid=0(root) groups=0(root)" if self.user == "root"
                    else f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)")
        if cmd == "hostname":
            return HOSTNAME
        if cmd == "uname":
            return UNAME_A if "-a" in args else ("x86_64" if "-m" in args else "Linux")
        if cmd == "pwd":
            return self.cwd
        if cmd == "cd":
            p = self._path(args[0] if args else "~")
            if p in FS:
                self.cwd = p
                return ""
            return f"-bash: cd: {args[0]}: No such file or directory"
        if cmd in ("ls", "dir", "ll"):
            targets = [a for a in args if not a.startswith("-")] or [self.cwd]
            p = self._path(targets[0])
            if p in FS:
                names = FS[p] if any("a" in a for a in args if a.startswith("-")) or cmd == "ll" \
                    else [n for n in FS[p] if not n.startswith(".")]
                return "  ".join(names)
            if p in FILES:
                return targets[0]
            return f"ls: cannot access '{targets[0]}': No such file or directory"
        if cmd == "cat":
            res = []
            for a in args:
                p = self._path(a)
                if p in FILES:
                    if p == "/etc/shadow" and self.user != "root":
                        res.append("cat: /etc/shadow: Permission denied")
                    else:
                        res.append(FILES[p].rstrip("\n"))
                elif p in FS:
                    res.append(f"cat: {a}: Is a directory")
                else:
                    res.append(f"cat: {a}: No such file or directory")
            return "\n".join(res).replace("\n", "\r\n")
        if cmd == "echo":
            return " ".join(a for a in args if a != "-e" and a != "-n")
        if cmd in ("wget", "curl"):
            urls = URL_RE.findall(cmdline) or [a for a in args if not a.startswith("-")][:1]
            host = re.sub(r"^\w+://", "", urls[0]).split("/")[0] if urls else ""
            if not host:
                return f"{cmd}: missing URL"
            if cmd == "curl":
                return f"curl: (28) Failed to connect to {host} port 80 after 21004 ms: Connection timed out"
            return (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {urls[0]}\r\n"
                    f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\r\n"
                    f"wget: unable to resolve host address '{host}'")
        if cmd in ("uptime", "w"):
            return " 10:42:17 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01"
        if cmd == "nproc":
            return "4"
        if cmd == "free":
            return ("               total        used        free      shared  buff/cache   available\r\n"
                    "Mem:         8141252     2190440     3101524       12872     2849288     5650812\r\n"
                    "Swap:        2097148           0     2097148")
        if cmd == "df":
            return ("Filesystem      Size  Used Avail Use% Mounted on\r\n"
                    "/dev/sda2        79G   23G   52G  31% /")
        if cmd in ("ifconfig", "ip"):
            return ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\r\n"
                    "    inet 10.10.20.14/24 brd 10.10.20.255 scope global eth0")
        if cmd == "ps":
            return ("    PID TTY          TIME CMD\r\n      1 ?        00:00:09 systemd\r\n"
                    "    812 ?        00:01:44 mysqld\r\n   1021 ?        00:00:00 sshd\r\n"
                    "   1337 pts/0    00:00:00 bash")
        if cmd == "history":
            return "    1  mysql -u root -p\r\n    2  cat /root/backup.sql\r\n    3  history"
        if cmd in ("chmod", "chown", "mkdir", "rm", "touch", "export", "unset", "cp", "mv",
                   "kill", "pkill", "crontab", "clear", "set", "alias", "source", "."):
            return ""
        if cmd in ("bash", "sh", "busybox") and not args:
            return ""
        return f"-bash: {cmd}: command not found"


# --------------------------------------------------------------------------- SSH
class Server(paramiko.ServerInterface):
    def __init__(self, ctx):
        self.ctx = ctx
        self.cv = threading.Condition()
        self.requests = {}  # id de canal -> commande exec, ou None pour un shell

    def _client(self):
        return self.ctx["transport"].remote_version if self.ctx.get("transport") else None

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        ok = (username, password) in ACCEPT
        c = self.ctx
        LOG.log("login_attempt", c["ip"], c["port"], c["sid"], username=username, password=password,
                auth_method="password", success=ok, client_version=self._client())
        if ok:
            c["user"] = username
            LOG.log("login_success", c["ip"], c["port"], c["sid"], username=username, password=password)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        c = self.ctx
        LOG.log("login_attempt", c["ip"], c["port"], c["sid"], username=username, auth_method="publickey",
                key_type=key.get_name(), fingerprint=key.get_fingerprint().hex(), success=False,
                client_version=self._client())
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_window_change_request(self, *a):
        return True

    def check_channel_env_request(self, *a):
        return True

    def _request(self, channel, cmd):
        with self.cv:
            self.requests[channel.get_id()] = cmd
            self.cv.notify_all()
        return True

    def check_channel_shell_request(self, channel):
        return self._request(channel, None)

    def check_channel_exec_request(self, channel, command):
        return self._request(channel, command.decode("utf-8", "replace"))

    def wait_request(self, chan, timeout=30):
        with self.cv:
            self.cv.wait_for(lambda: chan.get_id() in self.requests, timeout)
            return chan.get_id() in self.requests, self.requests.get(chan.get_id())


def log_command(ctx, line, shell):
    urls = URL_RE.findall(line)
    LOG.log("command", ctx["ip"], ctx["port"], ctx["sid"], username=ctx.get("user"),
            command=line, cwd=shell.cwd, url=urls[0] if urls else None)


def interactive(chan, ctx, shell):
    chan.settimeout(IDLE_TIMEOUT)
    chan.send(f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
              f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 10.10.20.2\r\n")
    chan.send(shell.prompt())
    buf = ""
    while True:
        data = chan.recv(1024)
        if not data:
            return
        text = data.decode("utf-8", "replace")
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\x1b.", "", text)  # flèches, séquences d'échappement
        for ch in text:
            if ch in "\r\n":
                chan.send("\r\n")
                line = buf.strip()
                buf = ""
                if line:
                    log_command(ctx, line, shell)
                    out, leave = shell.run(line)
                    if out:
                        chan.send(out + "\r\n")
                    if leave:
                        chan.send("logout\r\n")
                        return
                chan.send(shell.prompt())
            elif ch in "\x7f\x08":
                if buf:
                    buf = buf[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":
                buf = ""
                chan.send("^C\r\n" + shell.prompt())
            elif ch == "\x04":
                if not buf:
                    chan.send("logout\r\n")
                    return
            elif ch == "\t":
                continue
            elif ch.isprintable() and len(buf) < 4096:
                buf += ch
                chan.send(ch)


def serve_channel(chan, srv, ctx):
    try:
        got, cmd = srv.wait_request(chan)
        if not got:
            return
        shell = FakeShell(ctx["user"] or "root")
        if cmd is not None:
            log_command(ctx, cmd, shell)
            out, _ = shell.run(cmd)
            if out:
                chan.send(out + "\r\n")
            chan.send_exit_status(0)
        else:
            interactive(chan, ctx, shell)
            chan.send_exit_status(0)
    except Exception:  # noqa: BLE001
        pass
    finally:
        chan.close()


def handle(sock, addr, host_key, slots):
    ctx = {"ip": addr[0], "port": addr[1], "sid": new_session(), "user": None}
    start = time.time()
    t = None
    try:
        LOG.log("connection", ctx["ip"], ctx["port"], ctx["sid"], dst_port=PORT)
        t = paramiko.Transport(sock)
        ctx["transport"] = t
        t.local_version = BANNER
        t.add_server_key(host_key)
        srv = Server(ctx)
        t.start_server(server=srv)
        # plusieurs canaux par connexion (ssh host cmd, scp, shell...), un thread chacun
        deadline = time.time() + 3600
        while t.is_active() and time.time() < deadline:
            chan = t.accept(1)
            if chan is not None:
                threading.Thread(target=serve_channel, args=(chan, srv, ctx), daemon=True).start()
    except Exception as e:  # noqa: BLE001 — un client malformé ne doit jamais tuer le serveur
        ctx["error"] = type(e).__name__
    finally:
        LOG.log("session_closed", ctx["ip"], ctx["port"], ctx["sid"], username=ctx.get("user"),
                duration=round(time.time() - start, 2), error=ctx.get("error"),
                client_version=t.remote_version if t else None)
        try:
            if t:
                t.close()
            sock.close()
        finally:
            slots.release()


def load_host_key():
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "ssh_host_rsa_key")
    if not os.path.exists(path):
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(path)
        os.chmod(path, 0o600)
    return paramiko.RSAKey(filename=path)


def main():
    host_key = load_host_key()
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND, PORT))
    srv.listen(100)
    print(f"[ssh-honeypot] listening on {BIND}:{PORT}, log -> {LOG.path}", flush=True)
    while True:
        sock, addr = srv.accept()
        if not slots.acquire(blocking=False):
            sock.close()
            continue
        sock.settimeout(IDLE_TIMEOUT)
        threading.Thread(target=handle, args=(sock, addr, host_key, slots), daemon=True).start()


if __name__ == "__main__":
    main()
