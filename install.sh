#!/usr/bin/env bash
set -euo pipefail

# install_authentik_tak.sh
# Hardened authentik installer for Ubuntu + Docker Compose v2
# - dotenv-safe passwords
# - ensures docker + compose plugin
# - downloads official compose
# - patches port mappings to use COMPOSE_PORT_HTTP/COMPOSE_PORT_HTTPS
# - bootstraps admin + token
# - optionally applies blueprint

########################################
# Settings
########################################
INSTALL_DIR="/opt/authentik"
COMPOSE_URL="https://goauthentik.io/docker-compose.yml"
APPLY_BLUEPRINT="${APPLY_BLUEPRINT:-1}"   # set to 0 to skip blueprint apply

########################################
# Helpers
########################################
log() { echo -e "\n== $* =="; }
die() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

as_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    bash -lc "$*"
  else
    sudo bash -lc "$*"
  fi
}

# dotenv-safe random strings (alphanumeric only)
rand_alnum() {
  local len="${1:-32}"
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len"
}

prompt_default() {
  local prompt="$1" def="$2" var=""
  read -r -p "$prompt [$def]: " var || true
  [[ -z "${var:-}" ]] && echo "$def" || echo "$var"
}

strip_url() {
  local x="$1"
  x="${x#http://}"; x="${x#https://}"
  x="${x%%/*}"
  echo "$x"
}

########################################
# Questions
########################################
echo "== authentik + TAK automation =="
HTTP_PORT="$(prompt_default 'authentik http port number?' '9000')"
HTTPS_PORT="$(prompt_default 'authentik https port number?' '9001')"
read -r -p "Authentik Domain? (optional) []: " AUTH_DOMAIN || true
read -r -p "TAK Portal Domain? (required): " TAK_DOMAIN || true
[[ -z "${TAK_DOMAIN:-}" ]] && die "TAK Portal Domain is required."

AUTH_DOMAIN="$(strip_url "${AUTH_DOMAIN:-}")"
TAK_DOMAIN="$(strip_url "${TAK_DOMAIN}")"

LOCAL_BASE="http://127.0.0.1:${HTTP_PORT}"

########################################
# Install deps
########################################
log "Installing prerequisites (curl, jq, openssl, ca-certs)"
as_root "apt-get update -y"
as_root "apt-get install -y ca-certificates curl jq openssl gnupg lsb-release"

########################################
# Install Docker + Compose v2 plugin if missing
########################################
if ! need_cmd docker; then
  log "Installing Docker Engine + Compose v2 plugin"
  as_root "install -m 0755 -d /etc/apt/keyrings"
  as_root "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
  as_root "chmod a+r /etc/apt/keyrings/docker.gpg"
  as_root "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \\\"\\\$VERSION_CODENAME\\\") stable\" > /etc/apt/sources.list.d/docker.list"
  as_root "apt-get update -y"
  as_root "apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
fi

# Compose v2 check
if ! docker compose version >/dev/null 2>&1; then
  log "Installing docker-compose-plugin (Compose v2)"
  as_root "apt-get update -y"
  as_root "apt-get install -y docker-compose-plugin"
fi

log "Docker versions"
docker --version
docker compose version

########################################
# Prepare install directory
########################################
log "Preparing ${INSTALL_DIR}"
as_root "mkdir -p '${INSTALL_DIR}'"
# Make it writable by the invoking user (even if script is run as root)
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  # if run as root, keep root ownership
  :
else
  as_root "chown '${USER}:${USER}' '${INSTALL_DIR}'"
fi

cd "${INSTALL_DIR}"

########################################
# Download compose file
########################################
log "Downloading official docker-compose.yml"
curl -fsSLo docker-compose.yml "${COMPOSE_URL}"

########################################
# Patch compose ports to use env vars (robust)
########################################
log "Patching docker-compose.yml port mappings to use COMPOSE_PORT_HTTP/COMPOSE_PORT_HTTPS"

# We replace common fixed mappings like:
# - "9000:9000"
# - "9443:9443"
# With env-driven mappings:
# - "${COMPOSE_PORT_HTTP:-9000}:9000"
# - "${COMPOSE_PORT_HTTPS:-9443}:9443"
#
# This is intentionally conservative (only rewrites exact patterns).
#
as_root "python3 - <<'PY'
import re, pathlib
p = pathlib.Path('docker-compose.yml')
txt = p.read_text()

# Replace quoted and unquoted port mappings
txt2 = txt

# 9000 mapping -> env var
txt2 = re.sub(r'([\"\\\']?)9000:9000\\1', r'\"${COMPOSE_PORT_HTTP:-9000}:9000\"', txt2)

# 9443 mapping -> env var
txt2 = re.sub(r'([\"\\\']?)9443:9443\\1', r'\"${COMPOSE_PORT_HTTPS:-9443}:9443\"', txt2)

if txt2 != txt:
    p.write_text(txt2)
PY"

########################################
# Generate secrets (dotenv-safe)
########################################
AK_SECRET_KEY="$(openssl rand -base64 36 | tr -d '\n')"
PG_PASS="$(rand_alnum 28)"

BOOTSTRAP_PASSWORD="$(rand_alnum 24)"
BOOTSTRAP_TOKEN="$(rand_alnum 40)"  # bearer token for API
BOOTSTRAP_EMAIL="admin@${AUTH_DOMAIN:-local}"

LDAP_SERVICE_PW="$(rand_alnum 14)"
TAKPORTAL_PW="$(rand_alnum 20)"
TAKPORTAL_API_TOKEN_KEY="$(rand_alnum 64)"

########################################
# Write .env (no risky chars)
########################################
log "Writing .env"
cat > .env <<EOF
AUTHENTIK_SECRET_KEY=${AK_SECRET_KEY}
PG_PASS=${PG_PASS}

COMPOSE_PORT_HTTP=${HTTP_PORT}
COMPOSE_PORT_HTTPS=${HTTPS_PORT}

AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

########################################
# Pre-flight port conflict check
########################################
log "Checking for port conflicts"
as_root "ss -ltnp | awk '{print \$4}' | grep -E '(:${HTTP_PORT}\$|:${HTTPS_PORT}\$)' && echo 'WARNING: One of your chosen ports appears in use.' || true"

########################################
# Pull + Up
########################################
log "Pulling images"
docker compose pull

log "Starting containers"
docker compose up -d

log "Compose status"
docker compose ps || true

########################################
# Wait for API
########################################
log "Waiting for authentik API on ${LOCAL_BASE}"
for i in $(seq 1 150); do
  if curl -fsS "${LOCAL_BASE}/api/v3/root/config/" >/dev/null 2>&1; then
    echo "authentik is responding."
    break
  fi
  sleep 2
  if [[ "$i" -eq 150 ]]; then
    docker compose logs --tail=200 || true
    die "Timed out waiting for authentik API on ${LOCAL_BASE}"
  fi
done

########################################
# Blueprint (optional)
########################################
if [[ "${APPLY_BLUEPRINT}" == "1" ]]; then
  log "Writing blueprint (tak-blueprint.yaml)"

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
    identifiers:
      name: authentik-GlobalAdmin
    attrs:
      name: authentik-GlobalAdmin

  - model: authentik_policies_password.passwordpolicy
    state: present
    identifiers:
      name: default-password-change-password-policy
    attrs:
      name: default-password-change-password-policy
      min_length: 12
      min_uppercase: 1
      min_lowercase: 1
      min_symbols: 1
      min_digits: 1

  - model: authentik_flows.flow
    state: present
    identifiers:
      slug: ldap-authentication-flow
    attrs:
      name: ldap-authentication-flow
      title: LDAP Authentication
      designation: authentication

  - model: authentik_stages_identification.identificationstage
    state: present
    identifiers:
      name: ldap-identification-stage
    attrs:
      name: ldap-identification-stage
      user_fields: [username]

  - model: authentik_stages_password.passwordstage
    state: present
    identifiers:
      name: ldap-authentication-password
    attrs:
      name: ldap-authentication-password

  - model: authentik_stages_user_login.userloginstage
    state: present
    identifiers:
      name: ldap-authentication-login
    attrs:
      name: ldap-authentication-login
      session_duration: seconds=0

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 10
    attrs:
      stage: !Find [authentik_stages_identification.identificationstage, [name, "ldap-identification-stage"]]

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 20
    attrs:
      stage: !Find [authentik_stages_password.passwordstage, [name, "ldap-authentication-password"]]

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 100
    attrs:
      stage: !Find [authentik_stages_user_login.userloginstage, [name, "ldap-authentication-login"]]

  - model: authentik_providers_ldap.ldapprovider
    state: present
    identifiers:
      name: TAK LDAP
    attrs:
      name: TAK LDAP
      base_dn: DC=takldap
      bind_flow: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      bind_mode: cached
      search_mode: cached

  - model: authentik_core.application
    state: present
    identifiers:
      slug: tak-ldap
    attrs:
      name: TAK LDAP
      slug: tak-ldap
      provider: !Find [authentik_providers_ldap.ldapprovider, [name, "TAK LDAP"]]

  - model: authentik_providers_proxy.proxyprovider
    state: present
    identifiers:
      name: TAK Portal Proxy
    attrs:
      name: TAK Portal Proxy
      mode: forward_single
      external_host: https://${TAK_DOMAIN}
      authorization_flow: !Find [authentik_flows.flow, [slug, "default-provider-authorization-implicit-consent"]]
      token_validity: hours=14

  - model: authentik_core.application
    state: present
    identifiers:
      slug: tak-portal
    attrs:
      name: TAK Portal
      slug: tak-portal
      provider: !Find [authentik_providers_proxy.proxyprovider, [name, "TAK Portal Proxy"]]

  - model: authentik_core.user
    state: present
    identifiers:
      username: adm_ldapservice
    attrs:
      name: adm_ldapservice
      username: adm_ldapservice
      path: service_accounts
      password: ${LDAP_SERVICE_PW}

  - model: authentik_core.user
    state: present
    identifiers:
      username: adm_takportal
    attrs:
      name: adm_takportal
      username: adm_takportal
      password: ${TAKPORTAL_PW}
      groups:
        - !Find [authentik_core.group, [name, "authentik Admins"]]

  - model: authentik_core.token
    state: present
    identifiers:
      identifier: adm_takportal-api
    attrs:
      key: ${TAKPORTAL_API_TOKEN_KEY}
      user: !Find [authentik_core.user, [username, "adm_takportal"]]
      intent: api
EOF

  if [[ -n "${AUTH_DOMAIN}" ]]; then
    sed -i "s/__AUTH_DOMAIN__/${AUTH_DOMAIN}/g" tak-blueprint.yaml
  fi

  log "Attempting to create + apply blueprint via API"
  # Create blueprint
  CREATE_JSON="$(jq -n --arg name "TAK Bootstrap" --arg content "$(cat tak-blueprint.yaml)" '{name:$name, enabled:true, content:$content}')"

  BP_RESP="$(curl -fsS \
    -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${CREATE_JSON}" \
    "${LOCAL_BASE}/api/v3/managed/blueprints/")" || {
      echo "Blueprint create failed. You can still use authentik; check API/token."
      echo "Response (if any): ${BP_RESP:-<none>}"
      APPLY_BLUEPRINT=0
    }

  if [[ "${APPLY_BLUEPRINT}" == "1" ]]; then
    BP_ID="$(echo "$BP_RESP" | jq -r '.pk // .uuid // .id // empty')"
    if [[ -z "${BP_ID}" ]]; then
      echo "Could not parse blueprint id from response:"
      echo "$BP_RESP" | jq .
    else
      curl -fsS \
        -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "${LOCAL_BASE}/api/v3/managed/blueprints/${BP_ID}/apply/" >/dev/null || {
          echo "Blueprint apply failed. This is often due to schema differences between authentik versions."
          echo "You can apply the blueprint manually in the UI or adjust models/fields."
        }
    fi
  fi
fi

########################################
# Output credentials
########################################
log "Done"
echo "authentik URL (HTTP):   ${LOCAL_BASE}"
echo "authentik Admin UI:     ${LOCAL_BASE}/if/admin/"
echo
echo "Bootstrap admin email:      ${BOOTSTRAP_EMAIL}"
echo "Bootstrap admin password:   ${BOOTSTRAP_PASSWORD}"
echo "Bootstrap API token:        ${BOOTSTRAP_TOKEN}"
echo
echo "adm_ldapservice password:   ${LDAP_SERVICE_PW}"
echo "adm_takportal password:     ${TAKPORTAL_PW}"
echo "adm_takportal API key:      ${TAKPORTAL_API_TOKEN_KEY}"
echo
echo "Install dir: ${INSTALL_DIR}"
echo "Logs: cd ${INSTALL_DIR} && docker compose logs -f"
