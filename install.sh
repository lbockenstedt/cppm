#!/bin/bash
set -e

# Default Configuration
HUB_URL="auto"   # was ws://localhost:8765 (retired bare listener); auto-discover the unified :443 hub
SPOKE_ID="${SPOKE_ID:-cppm-$(hostname -s)}"
SPOKE_SECRET=""
HUB_SECRET=""
# Set to 1 by the matching flag. A value not given on this run is kept from the
# existing .env (see "Configuring Spoke Identity" below), so a re-run for a code
# update keeps the spoke's secrets and hub. SPOKE_ID is not kept: as before, it
# derives from the hostname unless --id is given, so a renamed clone takes its
# new name.
HUB_URL_GIVEN=""; SPOKE_SECRET_GIVEN=""; HUB_SECRET_GIVEN=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; HUB_URL_GIVEN=1; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; SPOKE_SECRET_GIVEN=1; shift ;;
        --hub-secret) HUB_SECRET="$2"; HUB_SECRET_GIVEN=1; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

echo "🚀 Installing ClearPass Policy Manager (CPPM) Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl

INSTALL_DIR="/opt/lm"
OLD_INSTALL_DIR="/opt/lm-manager"

# Cleanup legacy installation
if [ -d "$OLD_INSTALL_DIR" ]; then
    echo "🗑️  Removing legacy installation at $OLD_INSTALL_DIR..."
    rm -rf "$OLD_INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
mkdir -p /var/log/lm   # systemd `append:` won't create the parent dir → unit 206/EXEC on a clean box

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

cd "$INSTALL_DIR"

# ── Retire any legacy lm-generic-agent on this box ───────────────────────────
# Vendored from lm/agent/install_agent.sh:retire_legacy_agent — keep in sync.
# The legacy leaf (lm-generic-agent, /opt/lm/generic-agent/src/agent.py) is
# protocol-incompatible with the session-key-adopting hub: it has no
# SPOKE_UPDATE_SESSION_KEY / LOAD_ROLE handler, connects + passes mTLS but never
# adopts a session key, and the hub refuses to dispatch to it (every role on
# the box times out while the WS stays "online"). Purge it before the clone so
# even an aborted install can't leave the zombie connecting under this box's
# id. Idempotent + non-fatal if absent; never touches this installer's own unit
# ($SERVICE_NAME) — it's (re)written below.
SERVICE_NAME="lm-cppm"
retire_legacy_agent() {
    # Match the legacy leaf by BOTH its historical unit name AND — crucially —
    # by any unit whose definition ExecStarts the legacy path
    # (/opt/lm/generic-agent/src/agent.py). Older template-menu builders named
    # the unit variously (not always lm-generic-agent), so a name-only purge
    # silently misses it and the zombie keeps connecting. Never touch the
    # role-capable unit ($SERVICE_NAME) — the install (re)writes it below.
    local names="lm-generic-agent"
    local f
    # Scan ALL standard systemd unit dirs, not just /etc — older builders dropped
    # the unit under /lib or /usr/lib, so an /etc-only grep misses it entirely.
    for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service \
             /run/systemd/system/*.service \
             /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
        [ -e "$f" ] || continue
        if grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null; then
            names="$names $(basename "$f" .service)"
        fi
    done
    # Also ask systemd directly which unit (if any) currently has a process whose
    # ExecStart is the legacy path — catches a unit in a non-standard location.
    local u
    for u in $(systemctl list-units --type=service --state=running,failed --no-legend --plain 2>/dev/null | awk '{print $1}'); do
        if systemctl show "$u" -p ExecStart 2>/dev/null | grep -q "/opt/lm/generic-agent"; then
            names="$names ${u%.service}"
        fi
    done
    local svc purged=0
    for svc in $(printf '%s\n' $names | sort -u); do
        [ -n "$svc" ] || continue
        [ "$svc" = "$SERVICE_NAME" ] && continue   # protect the new role-capable unit
        if [ -e "/etc/systemd/system/${svc}.service" ] \
           || systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
            systemctl mask    "$svc" 2>/dev/null || true   # after rm → mask sticks (blocks manual restart)
            echo "🧹  Purged legacy leaf unit ${svc}.service."
            purged=1
        fi
    done
    # Also stop any live process still exec'ing the legacy path (belt-and-
    # suspenders if it was launched outside systemd), then remove the dir.
    if [ -d /opt/lm/generic-agent ]; then
        pkill -f "/opt/lm/generic-agent/src/agent.py" 2>/dev/null || true
        rm -rf /opt/lm/generic-agent
        echo "🧹  Removed legacy leaf dir /opt/lm/generic-agent."
        purged=1
    fi
    if [ "$purged" = 1 ]; then
        systemctl daemon-reload 2>/dev/null || true
        echo "    The role-capable ${SERVICE_NAME} now owns this box's spoke connection."
    fi
}
retire_legacy_agent

if [ -d "cppm/.git" ]; then
    echo "📂 CPPM repository already exists. Updating..."
    # Track the checked-out branch, not a hardcoded main, so a dev/qa host stays
    # on its branch. Detached HEAD falls back to main.
    cd cppm
    BR=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true); case "$BR" in ""|HEAD) BR=main ;; esac
    git fetch origin -q "$BR" && git reset --hard "origin/$BR"   # hard-sync (soft `git pull` no-ops on a diverged/detached clone)
    cd ..
else
    echo "🌐 Cloning CPPM Manager repository..."
    git clone --branch "${CPPM_BRANCH:-main}" https://github.com/lbockenstedt/cppm.git
fi

# The service user the unit runs as (User=svc_lm), shared with the rest of LM.
# Created here when missing: without it the chown below failed silently and
# systemd refused to start the unit (217/USER).
if ! id svc_lm >/dev/null 2>&1; then
    useradd -r -s /bin/false -M svc_lm
    echo "👤 Created service user svc_lm"
fi

# The git clone/reset above ran as root; the spoke runs as svc_lm and
# self-updates via `git reset --hard`/`git pull` as that user — root-owned
# .git/objects → "insufficient permission for adding an object" → self-update
# fails. Hand the repo to svc_lm + trust the dir (mirrors cs/netbox installers).
chown -R svc_lm:svc_lm "$INSTALL_DIR/cppm" 2>/dev/null || true
runuser -u svc_lm -- git config --global --add safe.directory "$INSTALL_DIR/cppm" 2>/dev/null || true

echo "🛠️ Setting up CPPM Manager..."
cd cppm

if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then
    rm -rf venv
fi
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
fi

# --- Persistence Configuration ---
echo "⚙️ Configuring Spoke Identity..."
ENV_FILE="$INSTALL_DIR/cppm/.env"
# >>> spoke-env (tests/test_install_env.py runs this block on its own)
# The whole read-modify-write of .env runs as svc_lm, not root, while holding
# the flock on the sidecar .env.lock that the running spoke also takes when it
# rotates SPOKE_SECRET/HUB_SECRET into this file (core
# control_plane._env_file_flock). The service keeps running until the restart
# below, so without the lock a rotation landing between the read and the write
# was overwritten with the stale value. Running as svc_lm matters because the
# directory belongs to svc_lm: a root installer opening, chowning or chmodding
# a path there would follow a symlink planted by a compromised service account
# onto any root-owned file. As svc_lm, a planted symlink reaches only what
# svc_lm can already reach, and mktemp creates the new .env owned by svc_lm,
# mode 0600, so root never chowns or chmods anything here. runuser and flock
# are both in util-linux. The values are passed in the environment of this one
# subshell only, never on a command line.
(
export ENV_FILE HUB_URL HUB_URL_GIVEN SPOKE_ID SPOKE_SECRET SPOKE_SECRET_GIVEN HUB_SECRET HUB_SECRET_GIVEN
runuser -u svc_lm -- flock "$ENV_FILE.lock" bash -e <<'SPOKE_ENV'
# env_get KEY: KEY's value in the existing .env, or "" when absent.
env_get() {
    [ -f "$ENV_FILE" ] && grep "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true
}
# env_set KEY VALUE: replace KEY's line (or add it) and keep every other line,
# so settings added by hand (CPPM_HOST, LM_CPPM_VERIFY_TLS, ...) and keys the
# spoke persists itself survive a re-run. The new file is made by mktemp
# (mode 0600) and renamed into place, so the secrets are never readable by
# other users, even briefly.
env_set() {
    local tmp
    tmp="$(mktemp "$ENV_FILE.XXXXXX")"
    { [ -f "$ENV_FILE" ] && grep -v "^$1=" "$ENV_FILE" || true; printf '%s=%s\n' "$1" "$2"; } > "$tmp"
    mv -f "$tmp" "$ENV_FILE"
}
# A value given on this run wins; otherwise keep the one already in .env, so a
# re-run without flags (a code update) keeps the secrets and the hub.
[ -n "$HUB_URL_GIVEN" ]      || HUB_URL="$(env_get HUB_URL)"
[ -n "$SPOKE_SECRET_GIVEN" ] || SPOKE_SECRET="$(env_get SPOKE_SECRET)"
[ -n "$HUB_SECRET_GIVEN" ]   || HUB_SECRET="$(env_get HUB_SECRET)"
HUB_URL="${HUB_URL:-auto}"
if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    # Keep the default PSK "lm-secret" (do NOT clear to "") so the =-attached
    # ExecStart below (--secret=$SPOKE_SECRET) resolves to "lm-secret" at
    # runtime — matching the prior bare `--secret` argparse const="lm-secret"
    # zero-touch behavior. Clearing to "" would make `--secret=` pass an empty
    # string (pending negotiation) instead of the default-PSK path.
    SPOKE_SECRET="lm-secret"
    echo "ℹ️  No pre-shared secret — spoke will connect with the default PSK 'lm-secret' (zero-touch; the hub auto-approves the default PSK or awaits admin approval in the LM WebUI)."
fi
env_set HUB_URL "$HUB_URL"
env_set SPOKE_ID "$SPOKE_ID"
env_set SPOKE_SECRET "$SPOKE_SECRET"
# The unit passes --hub-secret=$HUB_SECRET from this file; before, the value
# was never written, so --hub-secret was silently dropped.
env_set HUB_SECRET "$HUB_SECRET"
# Report the hub from here: a re-run without --hub keeps the .env value, which
# only this block knows (the parent shell still holds "auto").
echo "🌐 Hub Target: $HUB_URL"
SPOKE_ENV
)
# <<< spoke-env

# --- Systemd Service (For Remote/Independent Deployment) ---
echo "⚙️ Creating systemd service for auto-start..."
cat <<EOF > /etc/systemd/system/lm-cppm.service
[Unit]
Description=Lab Manager Spoke - CPPM Manager
After=network.target

[Service]
Type=simple
User=svc_lm
WorkingDirectory=$INSTALL_DIR/cppm
EnvironmentFile=$INSTALL_DIR/cppm/.env
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/cppm/src"
ExecStart=$INSTALL_DIR/cppm/venv/bin/python3 -m src.control_plane --id \$SPOKE_ID --secret=\$SPOKE_SECRET --hub \$HUB_URL --hub-secret=\$HUB_SECRET
StandardOutput=append:/var/log/lm/lm-cppm.log
StandardError=append:/var/log/lm/lm-cppm.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-cppm
# Start it now (and pick up new code on a re-install). enable alone left the unit
# inactive until the next reboot, so the spoke never connected to --hub.
systemctl restart lm-cppm

echo "🎉 CPPM Manager installation complete!"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
