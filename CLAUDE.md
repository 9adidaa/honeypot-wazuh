# CLAUDE.md — briefing du projet (honeypot-wazuh)

Plateforme de **honeypots from scratch** (web, SSH, FTP, Redis) + **SIEM Wazuh**
(décodeurs, ~45 règles MITRE, dashboard), déployée en une commande avec Vagrant.
Projet ESGI. **Gel du rendu : 2026-11-29.**

## Architecture

- **NIX01** `192.168.56.101` : honeypots web *SweetBuzz* (Flask/gunicorn :5000),
  SSH (paramiko, :2222), FTP (asyncio, :21), Redis (asyncio RESP, :6379) + auditd
  (privesc) + FIM + agent Wazuh. Honeypots sous l'utilisateur `honeypot`, un
  service systemd chacun, logs JSON lines dans `/var/log/honeypots/*.json`.
- **SRV01** `192.168.56.102` : Wazuh 4.14 all-in-one (manager + indexer +
  dashboard). Décodeur `hp-access`, règles web `1001xx`, privesc `1002xx`,
  FIM `100300`, SSH/FTP/Redis `1004xx`. Dashboard « Honeypot ».
- **Hôte Kali** `192.168.56.1` : poste d'attaque (nmap, nikto, sqlmap, hydra,
  redis-tools, ftp, sshpass, paramiko déjà installés).

## Déploiement

```bash
vagrant up                      # ~30 min ; SRV01_MEM=5120 si <16 Go de RAM
vagrant provision srv01         # redéploie décodeur+règles+dashboard
# si le garde-fou disque (20 Go) bloque un re-provision alors que la VM tourne :
vagrant ssh srv01 -c "sudo bash /vagrant/deploy/srv01.sh"      # redéploie les règles
vagrant ssh nix01 -c "sudo bash /vagrant/deploy/honeypots.sh"  # redéploie les honeypots
```

Les sources des honeypots/règles vivent dans le dépôt (`/vagrant` synchronisé) et
sont **copiées** vers `/opt/honeypots` et `/var/ossec/etc/` par les scripts deploy.
Éditer un honeypot = éditer le dépôt puis `install …/opt/honeypots/*.py && systemctl restart honeypot-*`.
Les fichiers de tests tournent directement depuis `/vagrant` (pas besoin de provision).

## Tests (toujours lire la sortie — ne jamais supposer qu'un test passe)

```bash
python3 tests/test_static.py                                   # hôte, sans VM
vagrant ssh nix01 -c "sudo bash /vagrant/tests/test_nix01.sh --trigger"
vagrant ssh srv01 -c "sudo /var/ossec/bin/wazuh-analysisd -t"  # valide les règles
vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh"
vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh --e2e"    # attaques réelles
vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh --since 10"
```

## Statut : VÉRIFIÉ SUR VM (2026-11-22)

`vagrant destroy -f && SRV01_MEM=5120 vagrant up` nominal : pas d'erreur `[x]`,
`[dashboard] Dashboard importé`, services `honeypot-ssh/ftp/redis` actifs.

| Test | Résultat |
|---|---|
| `test_static.py` | 75 OK / 0 FAIL |
| `test_nix01.sh --trigger` | 61 OK / 0 FAIL |
| `wazuh-analysisd -t` | OK (8611 règles chargées) |
| `test_srv01.sh` | 70 OK / 0 FAIL |
| `test_srv01.sh --e2e` | 74 OK / 0 FAIL (E2E web 10/10, SSH/FTP/Redis OK) |
| `test_srv01.sh --since 10` | 71 OK / 0 FAIL |

Attaques réelles depuis l'hôte Kali (`srcip 192.168.56.1`, toutes journalisées et
indexées) : `nmap -sV`, `nikto`, `sqlmap`, SQLi manuelle `admin' --`, `hydra` +
session SSH, FTP (web shell), `redis-cli` (CONFIG SET+SAVE→100446, SLAVEOF,
MODULE LOAD, FLUSHALL), `tools/attack_demo.py --slow`. Indexer : >7000 alertes
honeypot sur 15 min, IP source majoritaire `192.168.56.1`.

## Pièges non évidents (corrigés — ne pas réintroduire)

- **Parent natif 86600** : règle Suricata (`decoded_as json` + `timestamp` +
  `event_type`). Les règles honeypot JSON s'y rattachent (100399) ET à un parent
  racine `decoded_as json` (100400) ; les enfants acceptent **les deux**
  (`if_sid>100399,100400`). Ne pas supprimer 100400 (fallback si 86600 absent).
- **Règle native 92600** (`0850-audit_rules.xml`, "python script executed", niv 0)
  capte tout événement audit dont l'`exe` contient `python` et **masquait** nos
  règles privesc. Fix : parents `if_sid>80700,92600` sur 100200 et 100210-100218.
  `92600` est dans `BUILTIN_PARENTS` de `test_static.py`.
- **Nom d'agent = `nix01`** (minuscule, = hostname), pas `NIX01`. `AGENT_NAME` par
  défaut dans `test_srv01.sh` et les filtres `agent.name` des tests en dépendent.
- **Honeypot SSH & clients libssh** (hydra/medusa/ncrack/metasploit) : paramiko
  refusait leur handshake (strict-kex Terrapin → `MessageOrderError`, puis
  désaccord kex 30/34). Fix dans `ssh_honeypot.py` : `Transport(sock,
  strict_kex=False, disabled_algorithms={"kex":[...DH group/GEX...]})`. OpenSSH
  continue de fonctionner. **Ne pas** remettre le strict-kex.
- **Corrélation Redis 100446** (`CONFIG SET dir/dbfilename` + `SAVE`, même session,
  niv 14) est **enfant `if_sid` de 100445** : quand elle se déclenche, elle
  **remplace** 100445. Donc dans un scénario d'attaque (SAVE après CONFIG SET dans
  la même session TCP), on voit 100446 et **jamais** 100445 isolé. `redis-cli`
  ouvre une connexion par invocation → pour 100446, piper plusieurs commandes dans
  **un seul** `redis-cli` (ou un socket unique).
- **Garde-fou disque** de `provision.sh` : 20 Go min. La VM SRV01 n'a que ~7 Go
  libres après l'install Wazuh (31 Go total, indexer à ~77 % — sous le watermark
  85 %, OK pour tourner). Un `vagrant provision` complet échoue sur ce garde-fou ;
  pour redéployer, lancer directement `deploy/srv01.sh` sur la VM.
- **Indexer non exposé à l'hôte** : port `9200` écoute en local sur SRV01
  seulement. Requêter l'index `wazuh-alerts-*` depuis SRV01 (`localhost:9200`).
  Le dashboard (`443`) est joignable depuis l'hôte (`https://192.168.56.102`).
- **Secrets** : `.secrets/` est git-ignoré (mot de passe admin généré au déploiement).

## Convention de commit

Messages en français, un commit par correctif logique. Terminer par la ligne
`Co-Authored-By` fournie par la session. Travail sur `main` (comme l'historique).
