# Tests

| Script | Où | Commande |
|---|---|---|
| `test_static.py` | ton PC / n'importe où (sans VM) | `pip install flask==3.0.2 && python3 tests/test_static.py` |
| `test_nix01.sh` | NIX01 | `sudo bash tests/test_nix01.sh` |
| `test_srv01.sh` | SRV01 | `sudo bash tests/test_srv01.sh` |

## Scénario complet (≈ 3 min)

```bash
# 1. PC : code, XML, cohérence, appli lancée pour de vrai
python3 tests/test_static.py

# 2. Avec Vagrant, le dépôt est déjà copié dans /opt/honeypot-wazuh sur chaque VM
#    (test_nix01.sh --trigger est lancé automatiquement à la fin de `vagrant up`)
vagrant ssh nix01 -c "sudo bash /opt/honeypot-wazuh/tests/test_nix01.sh --trigger"

# 3. SRV01 : services, règles (logtest), attaques réelles, alertes privesc
vagrant ssh srv01 -c "sudo bash /opt/honeypot-wazuh/tests/test_srv01.sh --e2e"
vagrant ssh srv01 -c "sudo bash /opt/honeypot-wazuh/tests/test_srv01.sh --since 10"
```

Chaque script finit par `X OK, Y WARN, Z FAIL` et renvoie le code 1 s'il y a un FAIL.

`cases.tsv` = la liste des attaques web (une ligne = nom, règle attendue, requête HTTP, ligne de log attendue).
Pour tester une nouvelle règle : ajouter une ligne, les 3 scripts la prennent en compte.
