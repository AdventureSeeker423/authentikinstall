#!/usr/bin/env bash
set -euo pipefail

############################################
# Authentik + TAK bootstrap installer
# Ubuntu-focused
#
# Logging:
#   - Console + /var/log/authentik_tak_installer.log
############################################

LOG_FILE="/var/log/authentik_tak_installer.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE" || true

log() {
  local ts
  ts="$(date -Is)"
  echo "[$ts] $*" | tee -a "$LOG_FILE" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (or with sudo)."
  fi
}

# Preflight: fail fast on LXC where Docker-in-LXC commonly cannot work without host changes
preflight_environment() {
  local virt
  virt="$(systemd-detect-virt 2>/dev/null || true)"

  if [[ "$virt" == "lxc" ]]; then
    log "Detected LXC environment."
    cat >&2 <<'MSG'
This installer uses Docker containers. Docker inside an *unprivileged* LXC often cannot start containers
because the host blocks access to kernel sysctls (/proc/sys/*) and other required features.

To run this installer reliably, use:
  - a VM, bare metal, or
  - a *privileged* LXC with nesting enabled (host-side setting).

There is no safe way for an install script to bypass these host restrictions automatically.
MSG
    exit 2
  fi
}

rand_b64() {
  # URL-safe-ish base64 (no / + =), good for secrets/tokens
  local n="${1:-48}"
  python3 - <<PY
import secrets, string
alphabet = string.ascii_letters + string.digits + "-_"
print("".join(secrets.choice(alphabet) for _ in range($n)))
PY
}

rand_pw() {
  # strong-ish password, printable, avoids quotes
  local n="${1:-14}"
  python3 - <<PY
import secrets, string
alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+?"
print("".join(secrets.choice(alphabet) for _ in range($n)))
PY
}

install_deps() {
  log "Installing system dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    ca-certificates curl jq openssl \
    python3 python3-venv python3-pip \
    gnupg lsb-release

  # Docker install (Ubuntu repo version). If you prefer Docker's official repo, swap this section.
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing docker..."
    apt-get install -y docker.io
    systemctl enable --now docker
  else
    log "Docker already installed."
  fi

  # Docker compose plugin
  if ! docker compose version >/dev/null 2>&1; then
    log "Installing docker compose plugin..."
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
  else
    log "Docker Compose already available."
  fi
}

############################################
# Inputs (defaults for now)
############################################
get_inputs() {
  # For now: bypass prompts with defaults (as requested)
  # Toggle to "false" later to enable prompts.
  local BYPASS="${BYPASS_PROMPTS:-true}"

  AUTH_HTTP_PORT_DEFAULT="9000"
  AUTH_HTTPS_PORT_DEFAULT="9001"
  AUTH_DOMAIN_DEFAULT="https://auth.google.com"
  TAK_DOMAIN_DEFAULT="https://takportal.google.com"

  if [[ "$BYPASS" == "true" ]]; then
    AUTH_HTTP_PORT="${AUTH_HTTP_PORT_DEFAULT}"
    AUTH_HTTPS_PORT="${AUTH_HTTPS_PORT_DEFAULT}"
    AUTH_DOMAIN="${AUTH_DOMAIN_DEFAULT}"
    TAK_DOMAIN="${TAK_DOMAIN_DEFAULT}"
    log "Bypassing prompts with defaults:"
    log "  AUTH_HTTP_PORT=$AUTH_HTTP_PORT"
    log "  AUTH_HTTPS_PORT=$AUTH_HTTPS_PORT"
    log "  AUTH_DOMAIN=$AUTH_DOMAIN"
    log "  TAK_DOMAIN=$TAK_DOMAIN"
    return
  fi

  read -r -p "authentik http port number? [${AUTH_HTTP_PORT_DEFAULT}] " AUTH_HTTP_PORT
  AUTH_HTTP_PORT="${AUTH_HTTP_PORT:-$AUTH_HTTP_PORT_DEFAULT}"

  read -r -p "authentik https port number? [${AUTH_HTTPS_PORT_DEFAULT}] " AUTH_HTTPS_PORT
  AUTH_HTTPS_PORT="${AUTH_HTTPS_PORT:-$AUTH_HTTPS_PORT_DEFAULT}"

  read -r -p "Authentik Domain? (optional) [${AUTH_DOMAIN_DEFAULT}] " AUTH_DOMAIN
  AUTH_DOMAIN="${AUTH_DOMAIN:-$AUTH_DOMAIN_DEFAULT}"

  read -r -p "TAK Portal Domain? (optional) [${TAK_DOMAIN_DEFAULT}] " TAK_DOMAIN
  TAK_DOMAIN="${TAK_DOMAIN:-$TAK_DOMAIN_DEFAULT}"
}

############################################
# Compose deployment
############################################
setup_compose() {
  INSTALL_DIR="${INSTALL_DIR:-/opt/authentik}"
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  log "Preparing secrets and environment..."

  # Core secrets
  POSTGRES_PASSWORD="$(rand_pw 32)"
  AUTHENTIK_SECRET_KEY="$(rand_b64 64)"

  # Bootstrap admin (akadmin) password & API token
  BOOTSTRAP_PASSWORD="$(rand_pw 20)"
  BOOTSTRAP_TOKEN="$(rand_b64 48)"
  BOOTSTRAP_EMAIL="${BOOTSTRAP_EMAIL:-root@example.com}"

  # Service passwords requested
  ADM_LDAPSERVICE_PASSWORD="$(rand_pw 14)"
  ADM_TAKPORTAL_PASSWORD="$(rand_pw 14)"

  # Write .env
  cat > .env <<EOF
# Ports
AUTHENTIK_HTTP_PORT=${AUTH_HTTP_PORT}
AUTHENTIK_HTTPS_PORT=${AUTH_HTTPS_PORT}

# PostgreSQL
PG_PASS=${POSTGRES_PASSWORD}

# authentik
AUTHENTIK_SECRET_KEY=${AUTHENTIK_SECRET_KEY}

# bootstrap admin (akadmin)
AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

  log "Writing docker-compose.yml..."
  cat > docker-compose.yml <<'EOF'
services:
  postgresql:
    image: docker.io/library/postgres:16
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d authentik -U authentik"]
      interval: 10s
      timeout: 5s
      retries: 5
    environment:
      POSTGRES_PASSWORD: ${PG_PASS}
      POSTGRES_USER: authentik
      POSTGRES_DB: authentik
    volumes:
      - ./database:/var/lib/postgresql/data

  redis:
    image: docker.io/library/redis:7
    restart: unless-stopped
    command: ["redis-server", "--save", "60", "1", "--loglevel", "warning"]
    volumes:
      - ./redis:/data

  server:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_LOG_LEVEL: info
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${AUTHENTIK_BOOTSTRAP_TOKEN}
    ports:
      - "${AUTHENTIK_HTTP_PORT}:9000"
      - "${AUTHENTIK_HTTPS_PORT}:9443"
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started

  worker:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_LOG_LEVEL: info
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${AUTHENTIK_BOOTSTRAP_TOKEN}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
EOF

  log "Starting authentik stack with docker compose..."
  docker compose up -d

  log "Waiting for authentik API to come up on http://127.0.0.1:${AUTH_HTTP_PORT}/api/v3/ ..."
  for i in {1..120}; do
    if curl -fsS "http://127.0.0.1:${AUTH_HTTP_PORT}/api/v3/root/config/" >/dev/null 2>&1; then
      log "authentik API is reachable."
      return
    fi
    sleep 2
  done

  die "authentik did not become reachable in time. Check: docker compose logs -f"
}

############################################
# Python configurator
############################################
run_configurator() {
  cd "$INSTALL_DIR"

  log "Creating Python venv and installing Python dependencies..."
  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null
  pip install requests >/dev/null

  log "Writing configurator script..."
  cat > configure_authentik.py <<'PY'
import os
import sys
import json
import time
from urllib.parse import urlparse

import requests

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[{ts}] {msg}", file=sys.stderr)

class AK:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base}{path}"

    def get(self, path: str, **kw):
        return self.s.get(self._url(path), timeout=30, **kw)

    def post(self, path: str, payload: dict, **kw):
        return self.s.post(self._url(path), data=json.dumps(payload), timeout=30, **kw)

    def patch(self, path: str, payload: dict, **kw):
        return self.s.patch(self._url(path), data=json.dumps(payload), timeout=30, **kw)

    def put(self, path: str, payload: dict, **kw):
        return self.s.put(self._url(path), data=json.dumps(payload), timeout=30, **kw)

def must_ok(r: requests.Response, what: str):
    if 200 <= r.status_code < 300:
        return
    try:
        body = r.json()
    except Exception:
        body = r.text
    raise RuntimeError(f"{what} failed: HTTP {r.status_code} {body}")

def find_by_name(ak: AK, list_path: str, name: str):
    r = ak.get(list_path, params={"name": name})
    must_ok(r, f"list {list_path}")
    data = r.json()
    results = data.get("results", data)
    for obj in results:
        if obj.get("name") == name:
            return obj
    return None

def find_by_slug(ak: AK, list_path: str, slug: str):
    r = ak.get(list_path, params={"slug": slug})
    must_ok(r, f"list {list_path}")
    data = r.json()
    results = data.get("results", data)
    for obj in results:
        if obj.get("slug") == slug:
            return obj
    return None

def main():
    http_port = os.environ["AUTH_HTTP_PORT"]
    token = os.environ["AUTH_BOOTSTRAP_TOKEN"]
    auth_domain = os.environ.get("AUTH_DOMAIN", "").strip()
    tak_domain = os.environ.get("TAK_DOMAIN", "").strip()

    ldap_pw = os.environ["ADM_LDAPSERVICE_PASSWORD"]
    tak_pw = os.environ["ADM_TAKPORTAL_PASSWORD"]

    base = f"http://127.0.0.1:{http_port}/api/v3"
    ak = AK(base=base, token=token)

    r = ak.get("/root/config/")
    must_ok(r, "root/config")
    log("Authenticated to authentik API using bootstrap token.")

    # --- Groups ---
    global_admin = find_by_name(ak, "/core/groups/", "authentik-GlobalAdmin")
    if not global_admin:
        r = ak.post("/core/groups/", {"name": "authentik-GlobalAdmin"})
        must_ok(r, "create group authentik-GlobalAdmin")
        global_admin = r.json()
        log("Created group authentik-GlobalAdmin")
    else:
        log("Group exists: authentik-GlobalAdmin")

    admins = find_by_name(ak, "/core/groups/", "authentik Admins")
    if not admins:
        r = ak.post("/core/groups/", {"name": "authentik Admins", "is_superuser": True})
        must_ok(r, "create group authentik Admins")
        admins = r.json()
        log("Created group authentik Admins")
    else:
        log("Group exists: authentik Admins")

    # --- Users ---
    # adm_ldapservice
    r = ak.get("/core/users/", params={"username": "adm_ldapservice"})
    must_ok(r, "list users")
    results = r.json().get("results", [])
    if results:
        ldap_user = results[0]
        log("User exists: adm_ldapservice")
    else:
        r = ak.post("/core/users/", {
            "username": "adm_ldapservice",
            "name": "adm_ldapservice",
            "is_active": True,
            "path": "service_accounts",
        })
        must_ok(r, "create user adm_ldapservice")
        ldap_user = r.json()
        log("Created user adm_ldapservice")

    uid = ldap_user.get("pk") or ldap_user.get("id")
    r = ak.post(f"/core/users/{uid}/set_password/", {"password": ldap_pw})
    must_ok(r, "set_password adm_ldapservice")
    log("Set password for adm_ldapservice")

    # Add to authentik Admins (bootstrap permission set)
    r = ak.post(f"/core/groups/{admins['pk']}/add_user/", {"pk": uid})
    if r.status_code not in (200, 204):
        log(f"WARNING: add_user adm_ldapservice to authentik Admins failed: {r.status_code} {r.text}")
    else:
        log("Added adm_ldapservice to authentik Admins")

    # --- Password policy ---
    policy_name = "default-password-change-password-policy"
    existing_policy = find_by_name(ak, "/policies/password/", policy_name)
    policy_payload = {
        "name": policy_name,
        "execution_logging": True,
        "amount_uppercase": 1,
        "amount_lowercase": 1,
        "amount_digits": 1,
        "amount_symbols": 1,
        "length_min": 12,
        "symbol_charset": "!@#$%^&*()-_=+[]{};:,.<>/?",
        "error_message": "Password does not meet complexity requirements.",
    }
    if existing_policy:
        pid = existing_policy.get("pk") or existing_policy.get("id")
        r = ak.put(f"/policies/password/{pid}/", policy_payload)
        if r.status_code >= 400:
            log(f"WARNING: update password policy failed: {r.status_code} {r.text}")
        else:
            log("Updated password policy.")
    else:
        r = ak.post("/policies/password/", policy_payload)
        if r.status_code >= 400:
            log(f"WARNING: create password policy failed: {r.status_code} {r.text}")
        else:
            log("Created password policy.")

    # --- Brand domain ---
    if auth_domain:
        u = urlparse(auth_domain if "://" in auth_domain else f"https://{auth_domain}")
        brand_domain = u.netloc or auth_domain
    else:
        brand_domain = "authentik.local"

    brand_name = f"Brand for {brand_domain}"
    existing_brand = find_by_name(ak, "/core/brands/", brand_name)
    brand_payload = {"name": brand_name, "domain": brand_domain, "default": True}
    if existing_brand:
        bid = existing_brand.get("pk") or existing_brand.get("id")
        r = ak.patch(f"/core/brands/{bid}/", brand_payload)
        if r.status_code >= 400:
            log(f"WARNING: update brand failed: {r.status_code} {r.text}")
        else:
            log("Updated brand.")
    else:
        r = ak.post("/core/brands/", brand_payload)
        if r.status_code >= 400:
            log(f"WARNING: create brand failed: {r.status_code} {r.text}")
        else:
            log("Created brand.")

    # --- Minimal final outputs ---
    print("")
    print("========== OUTPUTS ==========")
    print(f"adm_ldapservice password: {ldap_pw}")
    print(f"adm_takportal  password: {tak_pw}")
    print("=============================")

if __name__ == "__main__":
    main()
PY

  log "Running configurator against authentik API..."
  export AUTH_HTTP_PORT="${AUTH_HTTP_PORT}"
  export AUTH_BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN}"
  export AUTH_DOMAIN="${AUTH_DOMAIN}"
  export TAK_DOMAIN="${TAK_DOMAIN}"
  export ADM_LDAPSERVICE_PASSWORD="${ADM_LDAPSERVICE_PASSWORD}"
  export ADM_TAKPORTAL_PASSWORD="${ADM_TAKPORTAL_PASSWORD}"

  set +e
  python configure_authentik.py 2> >(tee -a "$LOG_FILE" >&2) | tee -a "$LOG_FILE"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    log "Configurator exited with code $rc"
    log "Check log file: $LOG_FILE"
    exit $rc
  fi

  log "Done."
  log "Auth UI should be reachable at: http://<host>:${AUTH_HTTP_PORT}/"
  log "Bootstrap admin user: akadmin"
  log "Bootstrap admin password stored in ${INSTALL_DIR}/.env"
}

main() {
  need_root
  preflight_environment
  install_deps
  get_inputs
  setup_compose
  run_configurator

  log "Installer complete."
  log "TIP: View logs with: tail -f $LOG_FILE"
  log "TIP: View container logs with: cd $INSTALL_DIR && docker compose logs -f"
}

main "$@"
