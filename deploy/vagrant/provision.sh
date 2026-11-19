#!/usr/bin/env bash
# =============================================================================
# provision.sh <srv01|nix01> — lancé automatiquement par Vagrant (en root)
#
#  - copie le dépôt dans /opt/honeypot-wazuh (+ conversion CRLF -> LF, utile
#    si le dépôt a été cloné sous Windows)
#  - vérifications : Ubuntu 22.04/24.04, RAM, disque, IP host-only, Internet
#  - hostname / /etc/hosts / NTP
#  - srv01 : installe Wazuh (all-in-one) puis deploy/srv01.sh
#  - nix01 : crée l'utilisateur nix01, attend le manager, deploy/nix01.sh, tests
#
# Idempotent : relancer avec `vagrant provision` ne casse rien.
# =============================================================================
set -euo pipefail

ROLE="${1:-}"
SRV01_IP="${SRV01_IP:-192.168.56.102}"
NIX01_IP="${NIX01_IP:-192.168.56.101}"
WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
SRC="/vagrant"
DST="/opt/honeypot-wazuh"
SECRETS="$SRC/.secrets"

log()  { echo -e "\e[1;32m[+]\e[0m [$ROLE] $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m [$ROLE] $*"; }
die()  { echo -e "\e[1;31m[x]\e[0m [$ROLE] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "doit être lancé en root"
case "$ROLE" in
  srv01) MY_IP="$SRV01_IP"; MIN_RAM=3800; MIN_DISK=20000 ;;
  nix01) MY_IP="$NIX01_IP"; MIN_RAM=900;  MIN_DISK=5000  ;;
  *) die "usage: provision.sh <srv01|nix01>" ;;
esac
export DEBIAN_FRONTEND=noninteractive

# -----------------------------------------------------------------------------
# 1. Vérifications préalables
# -----------------------------------------------------------------------------
preflight() {
  log "Vérifications préalables"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "OS non supporté : ${PRETTY_NAME:-?} (Ubuntu 22.04 ou 24.04 requis)"
  case "${VERSION_ID:-}" in
    22.04|24.04) log "  OS : $PRETTY_NAME — OK" ;;
    *) die "Ubuntu ${VERSION_ID:-?} non supporté (22.04 ou 24.04 LTS requis)" ;;
  esac

  local arch; arch="$(uname -m)"
  [[ "$arch" == "x86_64" ]] && log "  Architecture : $arch — OK" || warn "  Architecture $arch non testée"

  local ram; ram=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
  (( ram >= MIN_RAM )) && log "  RAM : ${ram} Mo — OK" \
    || die "RAM insuffisante : ${ram} Mo (minimum ${MIN_RAM} Mo) -> augmenter SRV01_MEM/NIX01_MEM"

  local disk; disk=$(df -Pm / | awk 'NR==2{print $4}')
  (( disk >= MIN_DISK )) && log "  Disque libre : ${disk} Mo — OK" \
    || die "Disque insuffisant : ${disk} Mo libres (minimum ${MIN_DISK} Mo)"

  if ip -4 -o addr show | grep -q "inet ${MY_IP}/"; then
    log "  IP host-only ${MY_IP} — OK"
  else
    die "IP host-only ${MY_IP} absente (vérifier le réseau VirtualBox 192.168.56.0/24)"
  fi

  # On teste le fichier réellement téléchargé ensuite (la racine du site renvoie 403)
  local url code i
  if [[ "$ROLE" == "srv01" ]]; then
    url="https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  else
    url="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
  fi
  for i in 1 2 3; do
    code=$(curl -sS -o /dev/null -I -L --max-time 15 -w '%{http_code}' "$url" 2>/dev/null || true)
    [[ "$code" != "000" && -n "$code" ]] && break
    [[ $i -eq 3 ]] && die "pas d'accès Internet (packages.wazuh.com injoignable)"
    sleep 5
  done
  [[ "$code" == "200" ]] || die "$url répond HTTP $code (version Wazuh ${WAZUH_VERSION} introuvable ?)"
  log "  Internet + dépôt Wazuh — OK"
}

# -----------------------------------------------------------------------------
# 2. Copie du dépôt + base système
# -----------------------------------------------------------------------------
stage_repo() {
  log "Copie du dépôt dans $DST"
  rm -rf "$DST"
  mkdir -p "$DST"
  tar -C "$SRC" --exclude=.vagrant --exclude=.secrets --exclude=.git -cf - . | tar -C "$DST" -xf -
  find "$DST" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.xml' -o -name '*.tsv' \
       -o -name '*.conf' -o -name '*.rules' -o -name '*.service' -o -name '*.txt' \) \
       -exec sed -i 's/\r$//' {} +
  chmod +x "$DST"/deploy/*.sh "$DST"/tests/*.sh "$DST"/tests/*.py
}

base_system() {
  log "Hostname, /etc/hosts, NTP, paquets de base"
  hostnamectl set-hostname "$ROLE"
  sed -i '/ srv01$/d; / nix01$/d' /etc/hosts
  printf '%s srv01\n%s nix01\n' "$SRV01_IP" "$NIX01_IP" >> /etc/hosts
  timedatectl set-ntp true || true
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates gnupg tar python3 >/dev/null
}

# -----------------------------------------------------------------------------
# 3a. SRV01 : Wazuh all-in-one + règles honeypot
# -----------------------------------------------------------------------------
provision_srv01() {
  if [[ -x /var/ossec/bin/wazuh-control ]]; then
    log "Wazuh déjà installé — installation sautée"
  else
    log "Installation de Wazuh ${WAZUH_VERSION} all-in-one (10-20 min)..."
    cd /root
    curl -fsSO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
    bash wazuh-install.sh -a -i
  fi

  local pw=""
  if [[ -f /root/wazuh-install-files.tar ]]; then
    pw=$(tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
         | grep -A1 "indexer_username: 'admin'" | grep -oP "indexer_password: '\K[^']+" || true)
  fi
  if [[ -n "$pw" ]]; then
    mkdir -p "$SECRETS"
    printf 'Dashboard Wazuh : https://%s\nUtilisateur : admin\nMot de passe : %s\n' "$SRV01_IP" "$pw" \
      > "$SECRETS/wazuh-admin.txt"
    chmod 600 "$SECRETS/wazuh-admin.txt" 2>/dev/null || true
    log "Identifiants du dashboard enregistrés dans .secrets/wazuh-admin.txt (sur ton PC)"
  else
    warn "mot de passe admin introuvable dans /root/wazuh-install-files.tar"
  fi

  log "Déploiement du décodeur + des règles honeypot (deploy/srv01.sh)"
  bash "$DST/deploy/srv01.sh"
}

# -----------------------------------------------------------------------------
# 3b. NIX01 : honeypot + auditd + agent
# -----------------------------------------------------------------------------
provision_nix01() {
  if ! id nix01 >/dev/null 2>&1; then
    log "Création de l'utilisateur nix01"
    useradd -m -s /bin/bash nix01
  fi

  log "Attente du manager Wazuh ${SRV01_IP}:1515 (enrôlement)"
  local i
  for i in $(seq 1 60); do
    timeout 3 bash -c "</dev/tcp/${SRV01_IP}/1515" 2>/dev/null && break
    [[ $i -eq 60 ]] && die "manager injoignable sur ${SRV01_IP}:1515 (SRV01 est-il démarré ?)"
    sleep 5
  done
  log "  manager joignable"

  log "Déploiement du honeypot + agent (deploy/nix01.sh)"
  MANAGER_IP="$SRV01_IP" AGENT_NAME="NIX01" bash "$DST/deploy/nix01.sh"

  log "Attente de la connexion de l'agent..."
  for i in $(seq 1 24); do
    grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && break
    sleep 5
  done

  log "Tests de NIX01"
  MANAGER_IP="$SRV01_IP" bash "$DST/tests/test_nix01.sh" --trigger || warn "certains tests NIX01 ont échoué (voir ci-dessus)"
}

# -----------------------------------------------------------------------------
preflight
stage_repo
base_system
"provision_${ROLE}"

echo
log "================ ${ROLE^^} prêt ================"
if [[ "$ROLE" == "srv01" ]]; then
  log "Dashboard Wazuh : https://${SRV01_IP}  (identifiants : .secrets/wazuh-admin.txt)"
else
  log "Honeypot web     : http://${NIX01_IP}:5000"
  log "Dashboard Wazuh  : https://${SRV01_IP}"
  log "Test complet     : vagrant ssh srv01 -c 'sudo bash /opt/honeypot-wazuh/tests/test_srv01.sh --e2e'"
fi
