#!/bin/bash
set -e

DEFAULT_SERVER_URL="https://localhost:8443"
DEFAULT_CONFIG_DIR="/etc/vespid-agent"
DEFAULT_STATE_DIR="/var/lib/vespid-agent"
DEFAULT_LOG_DIR="/var/log/vespid-agent"
AGENT="vespid-agent"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Vespid Agent Agent — Installer

Usage: $0 [OPTIONS]

Options:
  --server URL       Vespid server URL (default: $DEFAULT_SERVER_URL)
  --no-start         Install but do not start the service
  --help             Show this help

The agent uses zero-touch auto-enrollment. The first time the agent
starts it will register itself with the server via POST /api/v1/enroll.
The resulting API key is persisted to
    /var/lib/vespid-agent/credentials.json
with mode 0600. If the server is in ``manual_approval`` mode the
agent keeps retrying in the background until an operator approves the
request. The server's existing self-heal auto-rotate flow is used to
issue a new key on 401 errors.

This script requires root privileges and runs on RPM-based Linux systems
(AlmaLinux, RHEL, Rocky, Fedora).

EOF
    exit 0
}

log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

install_rpm() {
    local pkg="$AGENT"
    if rpm -q "$pkg" &>/dev/null; then
        log "Package $pkg is already installed"
        return 0
    fi

    if command -v dnf &>/dev/null; then
        dnf install -y "$pkg" || true
    elif command -v yum &>/dev/null; then
        yum install -y "$pkg" || true
    else
        err "No RPM package manager found (dnf/yum)"
    fi
}

install_from_source() {
    warn "RPM package not found in repos, building from source..."

    if ! command -v cargo &>/dev/null; then
        err "Rust toolchain not found. Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi

    if [ ! -d /tmp/vespid-agent ]; then
        git clone https://github.com/vespid/hivemonitor.git /tmp/vespid-agent
    fi

    cd /tmp/vespid-agent
    cargo build --release --bin vespid-agent

    mkdir -p "$DEFAULT_CONFIG_DIR" "$DEFAULT_STATE_DIR" "$DEFAULT_LOG_DIR"

    cp target/release/$AGENT /usr/bin/$AGENT
    chmod 755 /usr/bin/$AGENT
}

create_user() {
    if ! getent group vespid-agent &>/dev/null; then
        groupadd -r vespid-agent
    fi
    if ! getent passwd vespid-agent &>/dev/null; then
        useradd -r -g vespid-agent -d "$DEFAULT_STATE_DIR" -s /sbin/nologin vespid-agent
    fi

    chown -R vespid-agent:vespid-agent "$DEFAULT_STATE_DIR" "$DEFAULT_LOG_DIR"
}

create_config() {
    if [ -f "$DEFAULT_CONFIG_DIR/agent.yaml" ]; then
        log "Config already exists at $DEFAULT_CONFIG_DIR/agent.yaml"
        return 0
    fi

    mkdir -p "$DEFAULT_CONFIG_DIR"

    cat > "$DEFAULT_CONFIG_DIR/agent.yaml" <<YAML
server:
  url: "${SERVER_URL:-$DEFAULT_SERVER_URL}"
  api_key: ""

agent:
  labels: {}

collectors:
  cpu:
    enabled: true
    interval_secs: 60
  memory:
    enabled: true
    interval_secs: 60
  disk:
    enabled: true
    interval_secs: 60
  network:
    enabled: true
    interval_secs: 60
    exclude_interfaces:
      - "lo"
  systemd:
    enabled: true
    interval_secs: 60

buffer:
  path: "${DEFAULT_STATE_DIR}/buffer"
  max_total_size: 67108864
  max_file_size: 8388608

transport:
  batch_size: 500
  flush_interval_secs: 30
  request_timeout_secs: 30
YAML

    chmod 640 "$DEFAULT_CONFIG_DIR/agent.yaml"
    chown root:vespid-agent "$DEFAULT_CONFIG_DIR/agent.yaml"
    log "Created config at $DEFAULT_CONFIG_DIR/agent.yaml"
}

install_service() {
    local service_file="/usr/lib/systemd/system/${AGENT}.service"

    if [ ! -f "$service_file" ]; then
        cp systemd/${AGENT}.service "$service_file"
    fi

    systemctl daemon-reload

    if [ "$NO_START" != "1" ]; then
        systemctl enable --now "$AGENT"
        sleep 2
        systemctl status "$AGENT" --no-pager || true
    fi
}

# === Main ===

SERVER_URL=""
NO_START=""

while [ $# -gt 0 ]; do
    case "$1" in
        --server) SERVER_URL="$2"; shift 2 ;;
        --token)  shift 2 ;;  # deprecated: auto-enroll is now the default
        --no-start) NO_START=1; shift ;;
        --help) usage ;;
        *) err "Unknown option: $1" ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root"
fi

log "Installing Vespid Agent Agent..."

install_rpm || install_from_source
create_user
create_config
install_service

log "Done!"
echo ""
echo "  Service: systemctl status vespid-agent"
echo "  Config:  $DEFAULT_CONFIG_DIR/agent.yaml"
echo "  Logs:    journalctl -u vespid-agent -f"
echo ""
