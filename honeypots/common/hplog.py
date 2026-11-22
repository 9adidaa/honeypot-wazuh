"""
hplog.py — journalisation commune des honeypots (JSON lines, un événement par ligne).

Chaque ligne est lue par l'agent Wazuh (<log_format>json</log_format>) puis décodée
par le décodeur JSON natif du manager. La clé `srcip` est volontairement nommée
comme le champ statique Wazuh pour que <same_source_ip/> fonctionne (brute force).

Format :
  {"timestamp": "2026-11-22T10:00:00.123456+00:00", "honeypot": "ssh",
   "event_type": "login_attempt", "srcip": "192.168.56.1", "src_port": 51234,
   "session": "a1b2c3d4e5f6", "username": "root", "password": "123456", ...}
"""
import datetime
import json
import os
import threading
import uuid

LOG_DIR = os.environ.get("HP_LOG_DIR", "/var/log/honeypots")
DATA_DIR = os.environ.get("HP_DATA_DIR", "/var/lib/honeypots")
MAX_FIELD = 2048  # tronque les champs pour garder des lignes raisonnables


def new_session():
    return uuid.uuid4().hex[:12]


def _clip(v):
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    if isinstance(v, str) and len(v) > MAX_FIELD:
        return v[:MAX_FIELD] + "...[truncated]"
    return v


class HoneypotLogger:
    def __init__(self, honeypot, log_dir=None):
        self.honeypot = honeypot
        self.log_dir = log_dir or LOG_DIR
        os.makedirs(self.log_dir, exist_ok=True)
        self.path = os.path.join(self.log_dir, f"{honeypot}.json")
        self._lock = threading.Lock()

    def log(self, event_type, srcip=None, src_port=None, session=None, **fields):
        ev = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "honeypot": self.honeypot,
            "event_type": event_type,
            "srcip": srcip,
            "src_port": src_port,
            "session": session,
        }
        for k, v in fields.items():
            if v is not None:
                ev[k] = _clip(v)
        line = json.dumps(ev, ensure_ascii=True, separators=(",", ":"))
        with self._lock:
            with open(self.path, "a", encoding="ascii") as f:
                f.write(line + "\n")
        return ev
