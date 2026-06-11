#!/bin/sh
set -eu

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help)
      echo "Usage: $0 [--force]"
      echo "Installs Odo systemd packaging. --force overwrites /etc/odo/odo.env."
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must run as root. Re-run with sudo." >&2
  exit 1
fi

ROOT="${ODO_INSTALL_ROOT:-}"
BIN_DIR="$ROOT/usr/local/bin"
ETC_DIR="$ROOT/etc/odo"
RESOURCE_DIR="$ETC_DIR/resources"
AUTH_DIR="$ETC_DIR/auth"
DATA_DIR="$ROOT/var/lib/odo"
LOG_DIR="$ROOT/var/log/odo"
SYSTEMD_DIR="$ROOT/etc/systemd/system"
ENV_FILE="$ETC_DIR/odo.env"
SERVICE_FILE="$SYSTEMD_DIR/odo.service"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

ODO_USER="${ODO_USER:-odo}"
ODO_GROUP="${ODO_GROUP:-odo}"

if [ -z "$ROOT" ]; then
  if ! getent group "$ODO_GROUP" >/dev/null 2>&1; then
    groupadd --system "$ODO_GROUP"
  fi
  if ! id "$ODO_USER" >/dev/null 2>&1; then
    useradd --system --gid "$ODO_GROUP" --home-dir /var/lib/odo --shell /usr/sbin/nologin "$ODO_USER"
  fi
fi

install -d -m 0750 "$ETC_DIR" "$RESOURCE_DIR" "$AUTH_DIR"
install -d -m 0750 "$DATA_DIR" "$LOG_DIR"
install -d -m 0755 "$BIN_DIR" "$SYSTEMD_DIR"

if [ -z "$ROOT" ]; then
  chown root:"$ODO_GROUP" "$ETC_DIR" "$RESOURCE_DIR" "$AUTH_DIR"
  chown "$ODO_USER":"$ODO_GROUP" "$DATA_DIR" "$LOG_DIR"
fi

BINARY_SOURCE="${ODO_BINARY:-}"
if [ -z "$BINARY_SOURCE" ]; then
  if [ -x "$REPO_ROOT/bin/odo" ]; then
    BINARY_SOURCE="$REPO_ROOT/bin/odo"
  elif [ -x "$REPO_ROOT/odo" ]; then
    BINARY_SOURCE="$REPO_ROOT/odo"
  fi
fi

if [ -n "$BINARY_SOURCE" ]; then
  install -m 0755 "$BINARY_SOURCE" "$BIN_DIR/odo"
  echo "Installed binary to $BIN_DIR/odo"
else
  echo "No local Odo binary found. Run 'make build' first, then re-run this script or copy Odo to $BIN_DIR/odo."
fi

install -m 0644 "$REPO_ROOT/packaging/systemd/odo.service" "$SERVICE_FILE"

if [ -f "$ENV_FILE" ] && [ "$FORCE" -ne 1 ]; then
  echo "Keeping existing $ENV_FILE. Pass --force to overwrite it."
else
  install -m 0640 "$REPO_ROOT/packaging/systemd/odo.env.example" "$ENV_FILE"
  if [ -z "$ROOT" ]; then
    chown root:"$ODO_GROUP" "$ENV_FILE"
  fi
  echo "Installed example environment file to $ENV_FILE"
fi

if [ -z "$ROOT" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
else
  echo "Skipping systemctl daemon-reload because ODO_INSTALL_ROOT is set or systemctl is unavailable."
fi

cat <<EOF

Next steps:
1. Edit $ENV_FILE and replace all change-me values.
2. Confirm APP_PUBLIC_URL, APP_BIND_ADDR, APP_DATA_DIR, APP_CONFIG_DIR, and APP_DB_PATH.
3. Start Odo:
   systemctl enable --now odo
4. Check health:
   curl -s http://127.0.0.1:8080/api/v1/health
EOF
