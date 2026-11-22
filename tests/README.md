# Tests

| Script | Où | Commande |
|---|---|---|
| `test_static.py` | ton PC / n'importe où (sans VM) | `pip install flask==3.0.2 paramiko && python3 tests/test_static.py` |
| `test_nix01.sh` | NIX01 | `sudo bash tests/test_nix01.sh [--trigger]` |
| `test_srv01.sh` | SRV01 | `sudo bash tests/test_srv01.sh [--e2e \| --since N]` |

## Ce qui est testé

| | test_static.py (PC) | test_nix01.sh | test_srv01.sh |
|---|---|---|---|
| Web SweetBuzz | appli lancée, `cases.tsv` rejoué, décodeur, règle prédite | service, port 5000, format access.log, IP non falsifiable | wazuh-logtest de chaque cas, brute force 404, `--e2e` vraies requêtes -> alertes |
| SSH / FTP / Redis | honeypots lancés + attaqués, JSON valide, champs, règles prédites, sha256 des uploads, `hp_cases.tsv` | services, ports 2222/21/6379, utilisateur `honeypot`, CAP_NET_BIND_SERVICE, bannières, événement JSON | wazuh-logtest de `hp_cases.tsv`, brute force 100410, corrélation Redis 100446, `--e2e` via `tools/attack_demo.py` -> alertes |
| privesc / FIM | clés auditd <-> règles | règles auditd chargées, `--trigger` | `--since N` |
| Dashboard | ndjson valide, références, à jour | – | objets présents via l'API, alertes indexées |
| Scripts / XML | bash -n, shellcheck, XML, srv01.sh == wazuh/manager | – | `wazuh-analysisd -t` |

## Scénario complet

```bash
# 1. PC : code, XML, cohérence, applis lancées pour de vrai
python3 tests/test_static.py

# 2. Dans les VM, /vagrant = le dépôt du PC (les modifs locales s'appliquent tout de suite)
#    (test_nix01.sh --trigger est aussi lancé automatiquement à la fin de `vagrant up`)
vagrant ssh nix01 -c "sudo bash /vagrant/tests/test_nix01.sh --trigger"

# 3. SRV01 : services, règles (logtest), attaques réelles, alertes privesc
vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh --e2e"
vagrant ssh srv01 -c "sudo bash /vagrant/tests/test_srv01.sh --since 10"
```

Chaque script finit par `X OK, Y WARN, Z FAIL` et renvoie le code 1 s'il y a un FAIL.

- `cases.tsv` = attaques web (nom, règle attendue, requête HTTP, ligne de log attendue).
- `hp_cases.tsv` = événements JSON SSH/FTP/Redis (nom, règle attendue, ligne JSON).

Pour tester une nouvelle règle : ajouter une ligne, les scripts la prennent en compte.
