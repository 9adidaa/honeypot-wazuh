#!/usr/bin/env python3
"""
redis_honeypot.py — honeypot Redis (port 6379) écrit pour le projet, asyncio pur (stdlib).

Implémente le protocole RESP (tableaux de bulk strings + commandes "inline"),
se présente comme un Redis 5.0.7 sans mot de passe et répond de façon crédible aux
commandes utilisées dans les attaques réelles :
  CONFIG SET dir/dbfilename + SAVE   (écriture de crontab / authorized_keys)
  SLAVEOF / REPLICAOF                (rogue master -> chargement de module)
  MODULE LOAD, EVAL (CVE-2022-0543), FLUSHALL, AUTH (brute force)

Journalise (JSON lines, /var/log/honeypots/redis.json) :
  connection, login_attempt (AUTH), command, cross_protocol, session_closed

Env : HP_REDIS_PORT (6379), HP_REDIS_BIND (0.0.0.0), HP_LOG_DIR, HP_DATA_DIR
"""
import asyncio
import fnmatch
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "common")]
from hplog import HoneypotLogger, new_session  # noqa: E402

PORT = int(os.environ.get("HP_REDIS_PORT", "6379"))
BIND = os.environ.get("HP_REDIS_BIND", "0.0.0.0")
MAX_ARGS = 1024
MAX_BULK = 1024 * 1024
MAX_CLIENTS = 64
IDLE_TIMEOUT = 300
START = time.time()

LOG = HoneypotLogger("redis")
_clients = 0

# état "serveur" partagé (comme un vrai Redis : visible par tous les clients)
CONFIG = {
    "dir": "/var/lib/redis", "dbfilename": "dump.rdb", "requirepass": "", "masterauth": "",
    "bind": "0.0.0.0", "port": str(PORT), "protected-mode": "no", "maxmemory": "0",
    "save": "900 1 300 10 60 10000", "appendonly": "no", "slave-read-only": "yes",
}
DB = {"session:4f1c2a": "admin", "cache:homepage": "<html>...</html>", "user:1001": "alice@example.com"}
STATE = {"role": "master", "master": None}


class Err(str):
    pass


def enc(v):
    """Encode une valeur Python en RESP."""
    if v is None:
        return b"$-1\r\n"
    if isinstance(v, Err):
        return b"-" + v.encode() + b"\r\n"
    if isinstance(v, bool):
        return b":%d\r\n" % int(v)
    if isinstance(v, int):
        return b":%d\r\n" % v
    if isinstance(v, (list, tuple)):
        return b"*%d\r\n" % len(v) + b"".join(enc(x) for x in v)
    if isinstance(v, Simple):
        return b"+" + v.encode() + b"\r\n"
    b = v if isinstance(v, bytes) else str(v).encode()
    return b"$%d\r\n%s\r\n" % (len(b), b)


class Simple(str):
    pass


OK = Simple("OK")


def info():
    up = int(time.time() - START)
    return (
        "# Server\r\nredis_version:5.0.7\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\n"
        f"arch_bits:64\r\nprocess_id:812\r\ntcp_port:{PORT}\r\nuptime_in_seconds:{up}\r\n"
        f"uptime_in_days:{up // 86400}\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n\r\n"
        f"# Clients\r\nconnected_clients:{_clients}\r\n\r\n# Memory\r\nused_memory:1047352\r\n"
        "used_memory_human:1.00M\r\n\r\n# Persistence\r\nrdb_last_save_time:1763800000\r\n\r\n"
        f"# Replication\r\nrole:{STATE['role']}\r\nconnected_slaves:0\r\n\r\n"
        f"# Keyspace\r\ndb0:keys={len(DB)},expires=0,avg_ttl=0\r\n"
    )


def unknown(verb, args):
    first = " ".join(f"'{a}'" for a in args[:3])
    return Err(f"ERR unknown command `{verb.lower()}`, with args beginning with: {first}")


def execute(verb, args, sess):
    """Retourne la réponse (valeur Python) ; sess['quit'] = True pour fermer."""
    n = len(args)
    if verb == "PING":
        return args[0] if args else Simple("PONG")
    if verb == "ECHO":
        return args[0] if n == 1 else Err("ERR wrong number of arguments for 'echo' command")
    if verb == "QUIT":
        sess["quit"] = True
        return OK
    if verb == "AUTH":
        user, pw = (args[0], args[1]) if n >= 2 else ("default", args[0] if args else "")
        LOG.log("login_attempt", sess["ip"], sess["port"], sess["sid"], username=user, password=pw, success=False)
        return Err("ERR Client sent AUTH, but no password is set")
    if verb == "INFO":
        return info()
    if verb == "CONFIG":
        sub = args[0].upper() if args else ""
        if sub == "GET" and n >= 2:
            out = []
            for k, v in CONFIG.items():
                if fnmatch.fnmatch(k, args[1].lower()):
                    out += [k, v]
            return out
        if sub == "SET" and n >= 3:
            CONFIG[args[1].lower()] = args[2]
            return OK
        if sub in ("RESETSTAT", "REWRITE"):
            return OK
        return Err("ERR Unknown subcommand or wrong number of arguments for '%s'. Try CONFIG HELP." % sub)
    if verb in ("SAVE",):
        return OK
    if verb == "BGSAVE":
        return Simple("Background saving started")
    if verb in ("SLAVEOF", "REPLICAOF"):
        if n == 2 and args[0].upper() == "NO" and args[1].upper() == "ONE":
            STATE.update(role="master", master=None)
        elif n == 2:
            STATE.update(role="slave", master=f"{args[0]}:{args[1]}")
        else:
            return Err(f"ERR wrong number of arguments for '{verb.lower()}' command")
        return OK
    if verb == "MODULE":
        sub = args[0].upper() if args else ""
        if sub == "LIST":
            return []
        if sub == "LOAD":
            return Err("ERR Error loading the extension. Please check the server logs.")
        return Err("ERR Unknown subcommand or wrong number of arguments.")
    if verb in ("EVAL", "EVALSHA"):
        return Err("ERR Error running script (call to f_5e3d0a0f): @user_script:1: Script attempted to access nonexistent global variable")
    if verb == "SET" and n >= 2:
        DB[args[0]] = args[1]
        return OK
    if verb == "GET" and n == 1:
        return DB.get(args[0])
    if verb == "DEL":
        return sum(1 for k in args if DB.pop(k, None) is not None)
    if verb == "EXISTS":
        return sum(1 for k in args if k in DB)
    if verb == "KEYS" and n == 1:
        return [k for k in DB if fnmatch.fnmatchcase(k, args[0])]
    if verb == "DBSIZE":
        return len(DB)
    if verb in ("FLUSHALL", "FLUSHDB"):
        DB.clear()
        return OK
    if verb == "TYPE" and n == 1:
        return Simple("string" if args[0] in DB else "none")
    if verb == "TTL":
        return -1 if args and args[0] in DB else -2
    if verb in ("EXPIRE", "PERSIST"):
        return 1 if args and args[0] in DB else 0
    if verb == "SELECT":
        return OK if args and args[0].isdigit() and int(args[0]) < 16 else Err("ERR DB index is out of range")
    if verb == "CLIENT":
        sub = args[0].upper() if args else ""
        if sub == "LIST":
            return f"id=7 addr={sess['ip']}:{sess['port']} fd=8 name= age=0 idle=0 flags=N db=0 cmd=client\n"
        if sub == "GETNAME":
            return None
        return OK
    if verb == "COMMAND":
        return []
    if verb == "TIME":
        t = time.time()
        return [str(int(t)), str(int((t % 1) * 1e6))]
    if verb == "SHUTDOWN":
        return Err("ERR Errors trying to SHUTDOWN. Check logs.")
    return unknown(verb, args)


async def read_command(r):
    """Lit une commande RESP ou inline. Retourne une liste de str, [] si ligne vide, None si EOF."""
    line = await r.readline()
    if not line:
        return None
    if line[:1] == b"*":
        try:
            count = int(line[1:].strip())
        except ValueError:
            raise ValueError("Protocol error: invalid multibulk length")
        if count > MAX_ARGS:
            raise ValueError("Protocol error: invalid multibulk length")
        argv = []
        for _ in range(max(count, 0)):
            hdr = await r.readline()
            if hdr[:1] != b"$":
                raise ValueError("Protocol error: expected '$'")
            size = int(hdr[1:].strip())
            if size < 0 or size > MAX_BULK:
                raise ValueError("Protocol error: invalid bulk length")
            data = await r.readexactly(size + 2)
            argv.append(data[:-2].decode("utf-8", "replace"))
        return argv
    return line.decode("utf-8", "replace").strip().split()


async def on_client(reader, writer):
    global _clients
    peer = writer.get_extra_info("peername") or ("?", 0)
    sess = {"ip": peer[0], "port": peer[1], "sid": new_session(), "quit": False}
    if _clients >= MAX_CLIENTS:
        writer.write(b"-ERR max number of clients reached\r\n")
        writer.close()
        return
    _clients += 1
    start, ncmd, err = time.time(), 0, None
    LOG.log("connection", sess["ip"], sess["port"], sess["sid"], dst_port=PORT)
    try:
        while not sess["quit"]:
            try:
                argv = await asyncio.wait_for(read_command(reader), IDLE_TIMEOUT)
            except ValueError as e:
                writer.write(b"-ERR " + str(e).encode() + b"\r\n")
                err = "protocol_error"
                break
            if argv is None:
                break
            if not argv:
                continue
            verb, args = argv[0].upper(), argv[1:]
            ncmd += 1
            # Redis ferme la connexion sur "POST" / "Host:" (attaque cross-protocol via HTTP)
            if verb in ("POST", "HOST:", "GET") and (verb != "GET" or (args and args[-1].startswith("HTTP/"))):
                LOG.log("cross_protocol", sess["ip"], sess["port"], sess["sid"], command=" ".join(argv))
                err = "cross_protocol"
                break
            if verb != "AUTH":  # le mot de passe est journalisé dans login_attempt
                LOG.log("command", sess["ip"], sess["port"], sess["sid"], command=" ".join([verb] + args),
                        verb=verb)
            writer.write(enc(execute(verb, args, sess)))
            await writer.drain()
    except asyncio.TimeoutError:
        err = "timeout"
    except (ConnectionError, OSError, asyncio.IncompleteReadError) as e:
        err = type(e).__name__
    finally:
        _clients -= 1
        LOG.log("session_closed", sess["ip"], sess["port"], sess["sid"], duration=round(time.time() - start, 2),
                commands=ncmd, error=err)
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def main():
    server = await asyncio.start_server(on_client, BIND, PORT)
    print(f"[redis-honeypot] listening on {BIND}:{PORT}, log -> {LOG.path}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
