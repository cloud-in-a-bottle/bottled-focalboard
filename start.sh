#!/bin/bash
# Launch Focalboard on OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (subdomain focalboard.<zone>; JWT-
#                              verifies and stamps
#                              X-OpenHost-Is-Owner: true)
#          → container :8090   (auth_proxy.py — token-injection
#                                sidecar, also re-verifies JWT
#                                via JWKS)
#          → 127.0.0.1:8000    (focalboard-server in single-user
#                                mode — accepts any request that
#                                carries the configured single-
#                                user token)
#
# Three auth gates layered:
#
#   1. OpenHost router: anonymous visitors (no zone_auth) get
#      302'd to /login; we never see them.  Owners arrive with
#      X-OpenHost-Is-Owner: true.
#   2. auth_proxy.py: cross-verifies the zone_auth JWT against
#      the router's JWKS.  Only when sub == "owner" does the
#      proxy proceed — defence in depth so a misconfigured router
#      can't expose data even on a public_paths slip.
#   3. focalboard-server: validates the single-user token on
#      every request via its own session check.  We never disable
#      this — even if the proxy is bypassed somehow, focalboard
#      still enforces token presence.
#
# We use bash specifically (not /bin/sh) because we want
# associative arrays + `[[ ... ]]` for cleaner first-boot bring-
# up logic.  This matches openhost-minio/start.sh.
set -euo pipefail

# -----------------------------------------------------------------
# Persistence
# -----------------------------------------------------------------
#
# OpenHost mounts the persistent app-data dir at
# OPENHOST_APP_DATA_DIR.  In a real deploy this resolves to
# /data/app_data/focalboard inside the container, with the same
# files visible on the host under the persistent app_data dir.
PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/focalboard}"
DATA_DIR="$PERSIST/focalboard-data"     # sqlite DB + uploaded files
CONFIG_DIR="$PERSIST/config"            # generated config.json + token
mkdir -p "$DATA_DIR" "$DATA_DIR/files" "$CONFIG_DIR"

# -----------------------------------------------------------------
# Bootstrap single-user token
# -----------------------------------------------------------------
#
# Focalboard's single-user mode requires the operator to set
# FOCALBOARD_SINGLE_USER_TOKEN to a fixed value before the server
# will start.  Every API call must carry that token (via the
# FOCALBOARDAUTHTOKEN cookie or Authorization: Bearer header).
#
# We generate a 64-char random token on first boot and persist it
# to disk under $CONFIG_DIR/single-user-token.txt.  The auth-proxy
# reads the same file on startup and uses it to stamp the cookie
# on the first owner visit.  Subsequent boots reuse the same
# token so existing browser cookies stay valid; rotating means
# deleting the file and clearing the cookie in the browser.
#
# We deliberately do NOT make the token derivable from anything
# else (zone domain, app name, ...).  It's a pure secret, only
# present on disk inside the persistent volume — a leak is
# scoped to that volume.
TOKEN_FILE="$CONFIG_DIR/single-user-token.txt"

if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "[start.sh] First boot: generating Focalboard single-user token"
    # 64 chars of base64 from /dev/urandom, restricted to URL-
    # and cookie-safe characters.  Focalboard treats the token
    # as an opaque string so any printable character would
    # work, but we keep it [a-zA-Z0-9] to avoid quoting headaches
    # in env vars and curl commands.
    TOKEN="$(head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 64)"
    umask 077
    printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
    umask 022
fi
FOCALBOARD_SINGLE_USER_TOKEN="$(cat "$TOKEN_FILE")"
export FOCALBOARD_SINGLE_USER_TOKEN

# -----------------------------------------------------------------
# Generate runtime config.json
# -----------------------------------------------------------------
#
# Focalboard reads its config from a JSON file (path passed via
# -config CLI flag).  We write a runtime-generated config to
# $CONFIG_DIR/config.json that:
#
#   * Pins the sqlite DB under $DATA_DIR/focalboard.db so it
#     persists across container restarts.
#   * Pins the uploaded-file dir under $DATA_DIR/files for the
#     same reason.
#   * Sets serverRoot to the public canonical URL.  Focalboard
#     uses this in WebSocket upgrade URLs and a few internal
#     redirects; without it the WS URL ends up as
#     http://localhost:8000/ws and the SPA fails to upgrade.
#   * Disables telemetry (we don't ship usage stats off-host).
#   * Disables localOnly so the server binds 0.0.0.0:8000 and
#     the auth-proxy on the same container can reach it via
#     loopback (rootless podman networking gotcha).
#
# We re-write the file every boot from the upstream template +
# overrides; this way an operator who upgrades the image and
# sees new config keys gets sane defaults without manual merge.
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-focalboard}"
SERVER_ROOT="https://${APP_NAME}.${ZONE_DOMAIN}"

CONFIG_FILE="$CONFIG_DIR/config.json"
cat > "$CONFIG_FILE" <<EOF
{
    "serverRoot": "${SERVER_ROOT}",
    "port": 8000,
    "dbtype": "sqlite3",
    "dbconfig": "${DATA_DIR}/focalboard.db",
    "useSSL": false,
    "webpath": "/opt/focalboard/pack",
    "filespath": "${DATA_DIR}/files",
    "telemetry": false,
    "session_expire_time": 31536000,
    "session_refresh_time": 18000,
    "localOnly": false,
    "enableLocalMode": false
}
EOF

# -----------------------------------------------------------------
# Launch focalboard-server
# -----------------------------------------------------------------
#
# focalboard-server binds 0.0.0.0:8000 because rootless podman
# networking can't always reach `127.0.0.1:8000` from a sibling
# process in the same container reliably (specifically: when
# the binding is on `127.0.0.1` only, the auth-proxy's HTTP
# client sometimes hits ECONNREFUSED on first try because the
# port-namespace setup races the bind).  Binding on 0.0.0.0
# avoids the race; the port is never exposed to the outside
# (8090 is the only EXPOSE'd port).
#
# -single-user puts the server in fixed-token mode where every
# request must carry FOCALBOARD_SINGLE_USER_TOKEN.  See the
# auth-proxy docstring for how that token gets onto each request.
echo "[start.sh] Starting focalboard-server (single-user, db=$DATA_DIR/focalboard.db, port 8000)"
cd /opt/focalboard
./bin/focalboard-server -single-user -config "$CONFIG_FILE" &
FB_PID=$!

# -----------------------------------------------------------------
# Wait for focalboard-server to bind before starting the
# auth-proxy.  Without this gate the proxy starts up, accepts an
# inbound connection from the OpenHost healthcheck, and tries to
# forward it before focalboard is ready, returning 502.  The
# router can interpret the 502 as "container failed to start" and
# kill us before we ever come up.
# -----------------------------------------------------------------
for _ in $(seq 1 30); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', 8000)) == 0 else 1)
" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$FB_PID" 2>/dev/null; then
        wait "$FB_PID" || true
        echo "[start.sh] focalboard-server exited before binding port 8000"
        exit 1
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Launch auth-proxy
# -----------------------------------------------------------------
#
# AUTH_PROXY_TOKEN_FILE is the same file start.sh wrote above;
# the proxy reads it on every cookie-set so an operator who
# rotates the token (delete the file, restart the container)
# doesn't need a separate proxy restart.
#
# AUTH_PROXY_JWKS_URL points at the OpenHost router's JWKS
# endpoint on the parent zone domain.  In production this is
# https://<zone-domain>/.well-known/jwks.json which is published
# by compute_space's router for any app to verify zone_auth JWTs
# against.
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8090 -> 127.0.0.1:8000"
# OPENHOST_ROUTER_URL is injected by compute_space at container
# start (see compute_space/core/data.py); it points at the
# OpenHost router via podman's host-loopback alias.  The
# auth-proxy fetches the JWKS from there to verify zone_auth
# JWTs.  We re-export it so the proxy sees it whether or not
# bash inherited it; on dev-host invocations without OpenHost,
# AUTH_PROXY_DEV_JWKS_URL can override.
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8090}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="8000"
export AUTH_PROXY_TOKEN_FILE="$TOKEN_FILE"
python3 /opt/openhost-focalboard/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------
#
# Forward SIGTERM to both children so a graceful stop reaches
# focalboard cleanly (it flushes the sqlite WAL on shutdown).
trap 'kill -TERM "$FB_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor.
# `wait -n` is bash-only; matches openhost-minio's pattern.
set +e
wait -n "$FB_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$FB_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
