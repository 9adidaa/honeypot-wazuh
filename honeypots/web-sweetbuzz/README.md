# SweetBuzz Honey Co. — Vulnerable Web Application

A deliberately vulnerable Flask + SQLite honeypot application used to exercise the Wazuh
detection platform. **Do not expose this application to the internet.**

## Vulnerabilities

| ID | Type | Endpoint | Flag |
|----|------|----------|------|
| V1 | SQL Injection (auth bypass) | `POST /login` | `CODEBY{HONEYPOT_SQLI_BYPASS_SUCCESS}` |
| V2 | HTTP Method Tampering | `DELETE /admin` | `CODEBY{METHOD_TAMPERING_MASTER}` |
| V3 | Stored Cross-Site Scripting | `POST /feedback` | — |

## Files

| File | Purpose |
|------|---------|
| `app.py` | The application (includes the Wazuh access-log hook) |
| `deploy.sh` | Installs dependencies, creates a venv, registers `honeypot.service` |
| `requirements.txt` | Python dependencies (`flask==3.0.2`, `gunicorn`) |
| `honeypot.service` | systemd unit (gunicorn, secret from `/etc/honeypots/sweetbuzz.env`) — installed by `deploy/nix01.sh` |

Sample captured log: [`docs/samples/access.log`](../../docs/samples/access.log)

## Quick Start

```bash
sudo apt install -y python3 python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py            # serves http://0.0.0.0:5000
```

Or run `sudo bash deploy.sh` to install it as a systemd service.

## Access Log

Every request is appended to `logs/access.log` in a token-safe, single-line format consumed by
the Wazuh decoder `hp-access`:

```
HONEYPOT-ACCESS src=<ip> method=<verb> path=<path> status=<code> body=<payload> ua=<user-agent> xff=<X-Forwarded-For|->
```
