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
        │  Honeypot web SweetBuzz :5000 │            │  Wazuh manager 4.14          │
        │    └─ logs/access.log         │  1514/tcp  │   ├─ décodeur hp-access      │
        │  auditd (règles privesc hp_*) ├───────────►│   ├─ ~20 règles honeypot     │
        │  FIM temps réel (Wazuh)       │   agent    │   ├─ Wazuh indexer           │
        │  Agent Wazuh                  │            │   └─ Wazuh dashboard (HTTPS) │
        └───────────────────────────────┘            └──────────────────────────────┘
```

## État d'avancement

**Terminé**
- [x] Honeypot web *SweetBuzz Honey Co.* (Flask) : SQLi, XSS stockée, contournement par la méthode HTTP
- [x] Journalisation de chaque requête (`HONEYPOT-ACCESS src=… method=… path=… body=… ua=… xff=…`)
- [x] Wazuh manager + agent, décodeur `hp-access`
- [x] ~20 règles de détection : SQLi, XSS, injection de commande, scanners, fichiers sensibles, brute force, élévation de privilèges (auditd), intégrité des fichiers (FIM), avec mapping MITRE ATT&CK
- [x] Scripts de déploiement idempotents `deploy/srv01.sh` et `deploy/nix01.sh`
- [x] Suite de tests (statique, NIX01, SRV01, bout en bout)
- [x] Déploiement automatique de A à Z : `vagrant up` (réseau, DHCP, vérifications, Wazuh, honeypot, agent, tests)

**En cours / à faire**
- [ ] Honeypot SSH (faux shell, enregistrement des commandes)
- [ ] Honeypot FTP (identifiants, capture des fichiers uploadés)
- [ ] Honeypot MySQL ou Redis
- [ ] Règles Wazuh pour les nouveaux honeypots
- [ ] Dashboard Wazuh dédié « Honeypot »
- [ ] Secrets dans un `.env`, correction de la falsification d'IP via `X-Forwarded-For`

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `Vagrantfile` | Déploiement complet du lab en une commande (`vagrant up`) |
| `deploy/` | `srv01.sh` (manager Wazuh + règles), `nix01.sh` (honeypot + auditd + agent), `vagrant/provision.sh` |
| `honeypots/web-sweetbuzz/` | Honeypot web (Flask) + service systemd |
| `wazuh/manager/` | Décodeur et règles de détection (copie de référence de ce que déploie `srv01.sh`) |
| `wazuh/agent/` | Bloc `ossec.conf` de l'agent + règles auditd (copie de référence de `nix01.sh`) |
| `tests/` | Tests automatiques (voir `tests/README.md`) |
| `tools/` | `show_alerts.py` : résumé des alertes honeypot sur le manager |
| `docs/` | Rapport technique, captures, exemple de log |

## Déploiement automatique (une commande)

**Prérequis sur le PC hôte :** [VirtualBox](https://www.virtualbox.org/) 7.x, [Vagrant](https://developer.hashicorp.com/vagrant/install) ≥ 2.3, 10 Go de RAM libres et environ 40 Go de disque.
Aucun ISO à télécharger : Vagrant récupère l'image Ubuntu 24.04 tout seul.

```bash
git clone https://github.com/<user>/honeypot-wazuh.git
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
| NIX01 | utilisateur `nix01`, attente du manager, `deploy/nix01.sh` (honeypot + auditd + agent), puis `tests/test_nix01.sh` |

Ensuite :
- Honeypot : http://192.168.56.101:5000
- Dashboard Wazuh : https://192.168.56.102 (les identifiants sont dans `.secrets/wazuh-admin.txt`)
- Test complet : `vagrant ssh srv01 -c "sudo bash /opt/honeypot-wazuh/tests/test_srv01.sh --e2e"`

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
python3 tests/test_static.py                  # sans VM : scripts, XML, règles, appli lancée + attaques
sudo bash tests/test_nix01.sh --trigger       # sur NIX01
sudo bash tests/test_srv01.sh --e2e           # sur SRV01 : règles + attaques réelles -> alertes
sudo bash tests/test_srv01.sh --since 10      # sur SRV01 : alertes privesc/FIM
```

## Avertissement

Le honeypot web contient des vulnérabilités **réelles et volontaires**. À n'utiliser que dans un
lab isolé, jamais exposé sur Internet. Les identifiants présents dans la documentation sont ceux des VM de lab.

## Équipe

| Membre | Rôle |
|---|---|
| … | … |
