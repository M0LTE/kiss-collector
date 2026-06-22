#!/usr/bin/env bash
# Install kiss-collector on a Debian/Ubuntu host (run as root).
# Override the broker with:  MQTT_HOST=mybroker.lan ./install.sh
set -euo pipefail

DEST=/opt/kisscollector
DBDIR=/var/lib/kisscollector
MQTT_HOST="${MQTT_HOST:-mqtt.lan}"
cd "$(dirname "$0")"

apt-get update
apt-get install -y python3 python3-paho-mqtt python3-flask python3-venv sqlite3

mkdir -p "$DEST" "$DBDIR"
install -m644 kisslib.py "$DEST/"
install -m755 collector.py webui.py mcpserver.py "$DEST/"

# venv for the MCP server (the 'mcp' package isn't in apt)
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install --quiet --upgrade pip
"$DEST/venv/bin/pip" install --quiet mcp

install -m644 systemd/*.service /etc/systemd/system/
sed -i "s/MQTT_HOST=mqtt.lan/MQTT_HOST=${MQTT_HOST}/" \
    /etc/systemd/system/kisscollector.service

systemctl daemon-reload
systemctl enable --now kisscollector kisscollector-web kisscollector-mcp
echo "Done. Web UI on :8080, MCP on :8765/mcp (broker: ${MQTT_HOST})"
