#!/bin/sh
set -eu

PURGE=0
YES=0
REMOVE_BINARY=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --yes|-y) YES=1 ;;
    --remove-binary) REMOVE_BINARY=1 ;;
    -h|--help)
      echo "Usage: $0 [--remove-binary] [--purge] [--yes]"
      echo "Stops Odo and removes the systemd unit. --purge also removes /etc/odo, /var/lib/odo, and /var/log/odo."
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This uninstaller must run as root. Re-run with sudo." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop odo.service >/dev/null 2>&1 || true
  systemctl disable odo.service >/dev/null 2>&1 || true
fi

rm -f /etc/systemd/system/odo.service

if [ "$REMOVE_BINARY" -eq 1 ]; then
  rm -f /usr/local/bin/odo
fi

if [ "$PURGE" -eq 1 ]; then
  if [ "$YES" -ne 1 ]; then
    echo "Purge will delete /etc/odo, /var/lib/odo, and /var/log/odo."
    printf "Type 'delete odo data' to continue: "
    read answer
    if [ "$answer" != "delete odo data" ]; then
      echo "Purge cancelled."
      exit 1
    fi
  fi
  rm -rf /etc/odo /var/lib/odo /var/log/odo
else
  echo "Keeping /etc/odo, /var/lib/odo, and /var/log/odo. Pass --purge to remove them."
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

echo "Odo systemd unit removed."
