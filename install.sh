#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# install_authentik_tak_verbose.sh
############################################

# ---------- Verbose logging ----------
TS="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/var/log/authentik-install-${TS}.log"
if ! ( touch "$LOGFILE" >/dev/null 2>&1 ); then
  LOGFILE="./authentik-install-${TS}.log"
  touch "$LOGFILE"
fi

export PS4='+ [$(date "+%F %T")] ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}() '
exec > >(tee -a "$LOGFILE") 2>&1
set -x

__ERR_HANDLED=0
on_err() {
  local ec=$?
  [[ "$__ERR_HANDLED" == "1" ]] && exit "$ec"
  __ERR_HANDLED=1
  echo
  echo "===== ERROR ====="
  echo "Exit code: $ec"
  echo "At line: ${BASH_LINENO[0]} in ${BASH_SOURCE[1]}"
  echo "Command: ${BASH_COMMAND}"
  echo "Log file: $LOGFILE"
  echo "============="
  echo
  exit "$ec"
}
trap on_err ERR

# ---------- Config ----------
INSTALL_DIR="/opt/authentik"
COMPOSE_URL="https://goauthentik.io/docker-compose.yml"
LOCALHOST="127.0.0.1"
APPLY_BLUEPRINT="${APPLY_BLUEPRINT:-1}"  # set to 0 to skip blueprint

# ---------- Helpers ----------
log() { echo -e "\n== $* =="; }

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    bash -lc "$*"
  else
    sudo bash -lc "$*"
  fi
}

strip_url() {
  local x="$1"
  x="${x#http://}"; x="${x#https://}"
  x="${x%%/*}"
  echo "$x"
}

prompt_default() {
  local prompt="$1" def="$2" val=""
  read -r -p "$prompt [$def]: " val || true
  [[ -z "${val:-}" ]] && echo "$def" || echo "$val"
}

# NO pipes, NO SIGPIPE: use python secrets
rand_alnum() {
  local len="${1:-32}"
  python3 - <<PY
import secrets, string
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range($len)), end='')
PY
}

# ---------- Questions ----------
echo "== authentik + TAK automation (VERBOSE) =="
echo "Log file: $LOGFILE"

HTTP_PORT="$(prompt_default 'authentik http port number?' '9000')"
HTTPS_PORT="$(prompt_default 'authentik https port number?' '9001')"

read -r -p "Authentik Domain? (optional) []: " AUTH_DOMAIN || true
read -r -p "TAK Portal Domain? (required): " TAK_DOMAIN || true
[[ -z "${TAK_DOMAIN:-}" ]] && { echo "TAK Portal Domain is required"; exit 1; }

AUTH_DOMAIN="$(strip_url "${AUTH_DOMAIN:-}")"
TAK_DOMAIN="$(strip_url "$TAK_DOMAIN")"

BASE_URL="http://${LOCALHOST}:${HTTP_PORT}"

VIRT="$(systemd-detect-virt 2>/dev/null || true)"
if [[ "$VIRT" == "lxc" || "$VIRT" == "container" ]]; then
  echo "NOTICE: Running inside '$VIRT'. Docker may be restricted (common in unprivileged LXC)."
fi

# ---------- Prereqs ----------
log "Installing prerequisites (curl, jq, openssl, ca-certs, python3)"
as_root "apt-get update -y"
as_root "apt-get install -y ca-certificates curl jq openssl gnupg lsb-release python3"

# ---------- Docker + Compose v2 ----------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine + Compose v2 plugin"
  as_root "install -m 0755 -d /etc/apt/keyrings"
  as_root "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
  as_root "chmod a+r /etc/apt/keyrings/docker.gpg"
  as_root "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \\\"\$VERSION_CODENAME\\\") stable\" > /etc/apt/sources.list.d/docker.list"
  as_root "apt-get update -y"
  as_root "apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
fi

if ! docker compose version >/dev/null 2>&1; then
  log "Installing docker-compose-plugin (Compose v2)"
  as_root "apt-get update -y"
  as_root "apt-get install -y docker-compose-plugin"
fi

log "Docker versions"
docker --version
docker compose version

# ---------- Prepare install dir ----------
log "Preparing ${INSTALL_DIR}"
as_root "mkdir -p '${INSTALL_DIR}'"
cd "${INSTALL_DIR}"

# ---------- Download compose ----------
log "Downloading official docker-compose.yml"
curl -fsSLo docker-compose.yml "${COMPOSE_URL}"

# ---------- Patch ports ----------
log "Patching docker-compose.yml to honor chosen host ports"
python3 <<'PY'
from pathlib import Path
p = Path("docker-compose.yml")
txt = p.read_text()
txt = txt.replace("9000:9000", "${COMPOSE_PORT_HTTP:-9000}:9000")
txt = txt.replace("9443:9443", "${COMPOSE_PORT_HTTPS:-9443}:9443")
p.write_text(txt)
PY

# ---------- Sysctl preflight + auto-mitigation ----------
log "Preflight: check whether Docker can apply container sysctls"
SYSCTL_TEST_OK=1
if ! docker run --rm --pull=never --sysctl net.ipv4.ip_unprivileged_port_start=1024 alpine:3.20 true >/dev/null 2>&1; then
  SYSCTL_TEST_OK=0
fi

if [[ "$SYSCTL_TEST_OK" -eq 0 ]]; then
  echo "WARNING: This environment blocks container sysctls."
  echo "         Removing 'net.ipv4.ip_unprivileged_port_start' from docker-compose.yml if present."
  python3 <<'PY'
from pathlib import Path
p = Path("docker-compose.yml")
lines = p.read_text().splitlines()
out = []
for line in lines:
    if "net.ipv4.ip_unprivileged_port_start" in line:
        continue
    out.append(line)
p.write_text("\n".join(out) + "\n")
PY
fi

grep -nE 'COMPOSE_PORT_HTTP|COMPOSE_PORT_HTTPS|sysctls|ip_unprivileged_port_start|9000:9000|9443:9443' docker-compose.yml || true

# ---------- Secrets ----------
log "Generating secrets (dotenv-safe, no SIGPIPE)"
AUTHENTIK_SECRET_KEY="$(openssl rand -base64 36 | tr -d '\n')"
PG_PASS="$(rand_alnum 28)"

BOOTSTRAP_EMAIL="admin@${AUTH_DOMAIN:-local}"
BOOTSTRAP_PASSWORD="$(rand_alnum 24)"
BOOTSTRAP_TOKEN="$(rand_alnum 40)"

LDAP_SERVICE_PW="$(rand_alnum 14)"
TAKPORTAL_PW="$(rand_alnum 20)"
TAKPORTAL_API_TOKEN_KEY="$(rand_alnum 64)"

# ---------- .env ----------
log "Writing .env"
cat > .env <<EOF
AUTHENTIK_SECRET_KEY=${AUTHENTIK_SECRET_KEY}
PG_PASS=${PG_PASS}

COMPOSE_PORT_HTTP=${HTTP_PORT}
COMPOSE_PORT_HTTPS=${HTTPS_PORT}

AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

# ---------- Port conflicts ----------
log "Checking for port conflicts on ${HTTP_PORT} / ${HTTPS_PORT}"
as_root "ss -ltnp | grep -E '(:${HTTP_PORT}\b|:${HTTPS_PORT}\b)' || true"

# ---------- Pull + Up ----------
log "docker compose pull"
docker compose pull

log "docker compose up -d"
docker compose up -d

log "docker compose ps"
docker compose ps || true

# ---------- Wait for API ----------
log "Waiting for authentik API at ${BASE_URL}"
for i in $(seq 1 180); do
  if curl -fsS "${BASE_URL}/api/v3/root/config/" >/dev/null 2>&1; then
    echo "authentik is responding."
    break
  fi
  sleep 2
  if [[ "$i" -eq 180 ]]; then
    echo "Timed out waiting for authentik API."
    docker compose logs --tail=250 || true
    exit 1
  fi
done

# ---------- Blueprint (best-effort) ----------
if [[ "$APPLY_BLUEPRINT" == "1" ]]; then
  log "Writing TAK blueprint (best-effort)"
  BRAND_ENTRY=""
  if [[ -n "${AUTH_DOMAIN}" ]]; then
    BRAND_ENTRY=$(cat <<'BEOF'
  - model: authentik_brands.brand
    state: present
    identifiers:
      domain: "__AUTH_DOMAIN__"
    attrs:
      domain: "__AUTH_DOMAIN__"
BEOF
)
  fi

  cat > tak-blueprint.yaml <<EOF
version: 1
metadata:
  name: TAK - Authentik bootstrap (LDAP + Proxy + Users)
entries:
${BRAND_ENTRY}
  - model: authentik_core.group
    state: present
    identifiers: { name: authentik-GlobalAdmin }
    attrs: { name: authentik-GlobalAdmin }

  - model: authentik_policies_password.passwordpolicy
    state: present
    identifiers: { name: default-password-change-password-policy }
    attrs:
      name: default-password-change-password-policy
      min_length: 12
      min_uppercase: 1
      min_lowercase: 1
      min_digits: 1
      min_symbols: 1

  - model: authentik_providers_ldap.ldapprovider
    state: present
    identifiers: { name: TAK LDAP }
    attrs:
      name: TAK LDAP
      base_dn: DC=takldap
      bind_mode: cached
      search_mode: cached

  - model: authentik_core.user
    state: present
    identifiers: { username: adm_ldapservice }
    attrs:
      name: adm_ldapservice
      username: adm_ldapservice
      path: service_accounts
      password: ${LDAP_SERVICE_PW}

  - model: authentik_core.user
    state: present
    identifiers: { username: adm_takportal }
    attrs:
      name: adm_takportal
      username: adm_takportal
      password: ${TAKPORTAL_PW}
      groups:
        - !Find [authentik_core.group, [name, "authentik Admins"]]

  - model: authentik_core.token
    state: present
    identifiers: { identifier: adm_takportal-api }
    attrs:
      key: ${TAKPORTAL_API_TOKEN_KEY}
      user: !Find [authentik_core.user, [username, "adm_takportal"]]
      intent: api
EOF

  if [[ -n "${AUTH_DOMAIN}" ]]; then
    sed -i "s/__AUTH_DOMAIN__/${AUTH_DOMAIN}/g" tak-blueprint.yaml
  fi

  log "Creating blueprint via API (best-effort)"
  CREATE_JSON="$(jq -n --arg name "TAK Bootstrap" --arg content "$(cat tak-blueprint.yaml)" '{name:$name, enabled:true, content:$content}')"

  BP_RESP="$(curl -fsS \
    -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${CREATE_JSON}" \
    "${BASE_URL}/api/v3/managed/blueprints/")" || {
      echo "Blueprint create failed (non-fatal)."
      APPLY_BLUEPRINT=0
    }

  if [[ "${APPLY_BLUEPRINT}" == "1" ]]; then
    BP_ID="$(echo "$BP_RESP" | jq -r '.pk // .uuid // .id // empty')"
    if [[ -n "${BP_ID}" ]]; then
      log "Applying blueprint via API (best-effort)"
      curl -fsS \
        -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "${BASE_URL}/api/v3/managed/blueprints/${BP_ID}/apply/" >/dev/null || {
          echo "Blueprint apply failed (non-fatal)."
        }
    fi
  fi
fi

# ---------- Done ----------
log "DONE"
echo "Log file:                 $LOGFILE"
echo "authentik URL (HTTP):      ${BASE_URL}/if/admin/"
echo
echo "Bootstrap admin email:     ${BOOTSTRAP_EMAIL}"
echo "Bootstrap admin password:  ${BOOTSTRAP_PASSWORD}"
echo "Bootstrap API token:       ${BOOTSTRAP_TOKEN}"
echo
echo "adm_ldapservice password:  ${LDAP_SERVICE_PW}"
echo "adm_takportal password:    ${TAKPORTAL_PW}"
echo "adm_takportal API key:     ${TAKPORTAL_API_TOKEN_KEY}"
echo
echo "Install dir: ${INSTALL_DIR}"
echo "Logs: cd ${INSTALL_DIR} && docker compose logs -f"
