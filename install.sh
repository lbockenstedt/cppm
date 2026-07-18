#!/bin/bash
set -e

# Default Configuration
HUB_URL="auto"   # was ws://localhost:8765 (retired bare listener); auto-discover the unified :443 hub
SPOKE_ID="${SPOKE_ID:-cppm-$(hostname -s)}"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
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

if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    # Keep the default PSK "lm-secret" (do NOT clear to "") so the =-attached
    # ExecStart below (--secret=$SPOKE_SECRET) resolves to "lm-secret" at
    # runtime — matching the prior bare `--secret` argparse const="lm-secret"
    # zero-touch behavior. Clearing to "" would make `--secret=` pass an empty
    # string (pending negotiation) instead of the default-PSK path.
    SPOKE_SECRET="lm-secret"
    echo "ℹ️  No pre-shared secret — spoke will connect with the default PSK 'lm-secret' (zero-touch; the hub auto-approves the default PSK or awaits admin approval in the LM WebUI)."
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
    cd cppm && git fetch origin -q && git reset --hard origin/main && cd ..   # hard-sync (soft `git pull` no-ops on a diverged/detached clone)
else
    echo "🌐 Cloning CPPM Manager repository..."
    git clone https://github.com/lbockenstedt/cppm.git
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
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
EOF

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
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
