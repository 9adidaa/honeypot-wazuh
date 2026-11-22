#!/usr/bin/env python3
"""
ftp_honeypot.py — honeypot FTP (port 21) écrit pour le projet, asyncio pur (stdlib).

Imite vsftpd 3.0.5 : USER/PASS, navigation, LIST/RETR sur un faux système de
fichiers, mode passif (PASV/EPSV) sur une petite plage de ports, et STOR :
les fichiers déposés sont conservés (nommés par leur sha256) pour analyse.

Journalise (JSON lines, /var/log/honeypots/ftp.json) :
  connection, login_attempt, login_success, command, file_upload, file_download,
  session_closed

Env : HP_FTP_PORT (21), HP_FTP_BIND (0.0.0.0), HP_FTP_PASV_MIN/MAX (30000-30009),
      HP_FTP_ACCEPT (user:pass,... ; "anonymous" accepte tout mot de passe),
      HP_LOG_DIR, HP_DATA_DIR
"""
import asyncio
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "common")]
from hplog import DATA_DIR, HoneypotLogger, new_session  # noqa: E402

PORT = int(os.environ.get("HP_FTP_PORT", "21"))
BIND = os.environ.get("HP_FTP_BIND", "0.0.0.0")
PASV_MIN = int(os.environ.get("HP_FTP_PASV_MIN", "30000"))
PASV_MAX = int(os.environ.get("HP_FTP_PASV_MAX", "30009"))
ACCEPT = {tuple(c.split(":", 1)) for c in os.environ.get(
    "HP_FTP_ACCEPT", "ftp:ftp,admin:admin,admin:123456,user:user,test:test,backup:backup").split(",") if ":" in c}
UPLOAD_DIR = os.path.join(DATA_DIR, "ftp_uploads")
MAX_UPLOAD = 20 * 1024 * 1024
MAX_CLIENTS = 64
IDLE_TIMEOUT = 300
BANNER = "220 (vsFTPd 3.0.5)"

LOG = HoneypotLogger("ftp")
_clients = 0

FS = {
    "/": {"pub": None, "backup": None, "readme.txt": b"Internal FTP - authorized staff only.\n"},
    "/pub": {"catalog_2026.pdf": b"%PDF-1.4\n% fake\n"},
    "/backup": {"db_2026-11-20.sql": b"-- MySQL dump\nINSERT INTO users VALUES (1,'admin','e10adc3949ba59abbe56e057f20f883e');\n",
                "config.php.bak": b"<?php $db_user='root'; $db_pass='Sup3rS3cret!'; ?>\n"},
}


def ls_line(name, size, is_dir):
    perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
    return f"{perm}    2 1000     1000     {size:>8} Nov 20 10:14 {name}\r\n"


class Session:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        peer = writer.get_extra_info("peername") or ("?", 0)
        self.ip, self.port = peer[0], peer[1]
        self.local_ip = (writer.get_extra_info("sockname") or ("127.0.0.1",))[0]
        self.sid = new_session()
        self.user = None
        self.authed = False
        self.cwd = "/"
        self.pasv_server = None
        self.data_conn = None  # Future -> (reader, writer)
        self.uploaded = {}     # fichiers déposés pendant la session (visibles dans LIST)
        self.rnfr = None

    def log(self, event, **kw):
        LOG.log(event, self.ip, self.port, self.sid, username=self.user, **kw)

    async def send(self, line):
        self.w.write((line + "\r\n").encode())
        await self.w.drain()

    # ------------------------------------------------------------------ données
    async def open_pasv(self):
        await self.close_pasv()
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        def on_conn(reader, writer):
            if fut.done():
                writer.close()
            else:
                fut.set_result((reader, writer))

        for p in range(PASV_MIN, PASV_MAX + 1):
            try:
                self.pasv_server = await asyncio.start_server(on_conn, self.local_ip, p)
                self.data_conn = fut
                return p
            except OSError:
                continue
        return None

    async def close_pasv(self):
        if self.pasv_server:
            self.pasv_server.close()
            self.pasv_server = None
        self.data_conn = None

    async def get_data(self):
        if not self.data_conn:
            await self.send("425 Use PORT or PASV first.")
            return None
        try:
            return await asyncio.wait_for(self.data_conn, 20)
        except asyncio.TimeoutError:
            await self.send("425 Failed to establish connection.")
            await self.close_pasv()
            return None

    # ------------------------------------------------------------------ fs
    def path(self, arg):
        p = arg if arg.startswith("/") else (self.cwd.rstrip("/") + "/" + arg)
        parts = []
        for part in p.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts)

    def listing(self, d):
        entries = dict(FS.get(d, {}))
        entries.update({n: v for (dd, n), v in self.uploaded.items() if dd == d})
        return entries

    # ------------------------------------------------------------------ commandes
    async def handle(self, verb, arg):
        if verb == "USER":
            self.user, self.authed = arg, False
            return await self.send("331 Please specify the password.")
        if verb == "PASS":
            if self.user is None:
                return await self.send("503 Login with USER first.")
            ok = self.user.lower() == "anonymous" or (self.user, arg) in ACCEPT
            self.log("login_attempt", password=arg, success=ok)
            if ok:
                self.authed = True
                self.log("login_success", password=arg)
                return await self.send("230 Login successful.")
            await asyncio.sleep(1)  # comme vsftpd : délai après échec
            return await self.send("530 Login incorrect.")
        if verb == "QUIT":
            await self.send("221 Goodbye.")
            return "quit"
        if verb in ("AUTH", "PBSZ", "PROT"):
            return await self.send("530 Please login with USER and PASS.")
        if verb == "FEAT":
            return await self.send("211-Features:\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n UTF8\r\n211 End")
        if verb == "SYST":
            return await self.send("215 UNIX Type: L8")
        if verb == "OPTS":
            return await self.send("200 Always in UTF8 mode.")
        if verb == "NOOP":
            return await self.send("200 NOOP ok.")
        if verb == "HELP":
            return await self.send("214 Help OK.")
        if not self.authed:
            return await self.send("530 Please login with USER and PASS.")

        if verb in ("PWD", "XPWD"):
            return await self.send(f'257 "{self.cwd}" is the current directory')
        if verb in ("CWD", "XCWD", "CDUP"):
            p = self.path(".." if verb == "CDUP" else (arg or "/"))
            if p in FS:
                self.cwd = p
                return await self.send("250 Directory successfully changed.")
            return await self.send("550 Failed to change directory.")
        if verb == "TYPE":
            return await self.send(f"200 Switching to {'Binary' if arg.upper().startswith('I') else 'ASCII'} mode.")
        if verb in ("MODE", "STRU"):
            return await self.send("200 OK.")
        if verb == "PASV":
            p = await self.open_pasv()
            if p is None:
                return await self.send("425 Could not open passive connection.")
            h = self.local_ip.replace(".", ",")
            return await self.send(f"227 Entering Passive Mode ({h},{p >> 8},{p & 255}).")
        if verb == "EPSV":
            p = await self.open_pasv()
            if p is None:
                return await self.send("425 Could not open passive connection.")
            return await self.send(f"229 Entering Extended Passive Mode (|||{p}|)")
        if verb in ("PORT", "EPRT"):
            self.log("active_mode_request", data=arg)  # PORT peut servir au "FTP bounce"
            return await self.send("500 Illegal PORT command.")
        if verb in ("LIST", "NLST", "MLSD"):
            target = self.path(arg) if arg and not arg.startswith("-") else self.cwd
            conn = await self.get_data()
            if not conn:
                return
            await self.send("150 Here comes the directory listing.")
            _, dw = conn
            for name, v in self.listing(target).items():
                dw.write((name + "\r\n").encode() if verb == "NLST"
                         else ls_line(name, 4096 if v is None else len(v), v is None).encode())
            await dw.drain()
            dw.close()
            await self.close_pasv()
            return await self.send("226 Directory send OK.")
        if verb == "RETR":
            p = self.path(arg)
            d, name = p.rsplit("/", 1)
            content = self.listing(d or "/").get(name)
            if content is None:
                return await self.send("550 Failed to open file.")
            conn = await self.get_data()
            if not conn:
                return
            await self.send(f"150 Opening BINARY mode data connection for {name} ({len(content)} bytes).")
            _, dw = conn
            dw.write(content)
            await dw.drain()
            dw.close()
            await self.close_pasv()
            self.log("file_download", filename=p, size=len(content))
            return await self.send("226 Transfer complete.")
        if verb in ("STOR", "APPE", "STOU"):
            return await self.stor(arg or f"stou_{int(time.time())}")
        if verb == "SIZE":
            d, name = self.path(arg).rsplit("/", 1)
            content = self.listing(d or "/").get(name)
            return await self.send(f"213 {len(content)}" if content is not None else "550 Could not get file size.")
        if verb == "MDTM":
            return await self.send("213 20261120101400")
        if verb in ("DELE", "RMD", "XRMD", "MKD", "XMKD", "RNTO"):
            return await self.send("550 Permission denied.")
        if verb == "RNFR":
            self.rnfr = arg
            return await self.send("350 Ready for RNTO.")
        if verb == "REST":
            return await self.send(f"350 Restart position accepted ({arg}).")
        if verb == "SITE":
            return await self.send("500 Unknown SITE command.")
        return await self.send("500 Unknown command.")

    async def stor(self, arg):
        p = self.path(arg)
        conn = await self.get_data()
        if not conn:
            return
        await self.send("150 Ok to send data.")
        dr, dw = conn
        h, size, chunks, truncated = hashlib.sha256(), 0, [], False
        try:
            while True:
                buf = await asyncio.wait_for(dr.read(65536), 60)
                if not buf:
                    break
                if size + len(buf) > MAX_UPLOAD:
                    buf = buf[:MAX_UPLOAD - size]
                    truncated = True
                h.update(buf)
                chunks.append(buf)
                size += len(buf)
                if truncated:
                    break
        except asyncio.TimeoutError:
            truncated = True
        dw.close()
        await self.close_pasv()
        digest = h.hexdigest()
        data = b"".join(chunks)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        stored = os.path.join(UPLOAD_DIR, digest)
        if not os.path.exists(stored):
            with open(stored, "wb") as f:
                f.write(data)
        d, name = p.rsplit("/", 1)
        self.uploaded[(d or "/", name)] = data
        self.log("file_upload", filename=p, size=size, sha256=digest, stored=stored, truncated=truncated)
        await self.send("226 Transfer complete.")

    async def run(self):
        start = time.time()
        self.log("connection", dst_port=PORT)
        err = None
        try:
            await self.send(BANNER)
            while True:
                raw = await asyncio.wait_for(self.r.readline(), IDLE_TIMEOUT)
                if not raw:
                    break
                line = raw[:2048].decode("utf-8", "replace").strip()
                if not line:
                    continue
                verb, _, arg = line.partition(" ")
                verb = verb.upper()
                if verb != "PASS":  # le mot de passe est journalisé dans login_attempt
                    self.log("command", command=f"{verb} {arg}".strip())
                if await self.handle(verb, arg.strip()) == "quit":
                    break
        except asyncio.TimeoutError:
            err = "timeout"
        except (ConnectionError, OSError) as e:
            err = type(e).__name__
        finally:
            await self.close_pasv()
            self.log("session_closed", duration=round(time.time() - start, 2), error=err)
            try:
                self.w.close()
            except Exception:  # noqa: BLE001
                pass


async def on_client(reader, writer):
    global _clients
    if _clients >= MAX_CLIENTS:
        writer.write(b"421 There are too many connected users, please try later.\r\n")
        writer.close()
        return
    _clients += 1
    try:
        await Session(reader, writer).run()
    finally:
        _clients -= 1


async def main():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    server = await asyncio.start_server(on_client, BIND, PORT)
    print(f"[ftp-honeypot] listening on {BIND}:{PORT} (PASV {PASV_MIN}-{PASV_MAX}), log -> {LOG.path}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
