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
cd "$INSTALL_DIR"

if [ -d "cppm/.git" ]; then
    echo "📂 CPPM repository already exists. Updating..."
    cd cppm && git pull && cd ..
else
    echo "🌐 Cloning CPPM Manager repository..."
    git clone https://github.com/lbockenstedt/cppm.git
fi

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

echo "🎉 CPPM Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
