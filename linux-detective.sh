#!/bin/sh
# =============================================================================
#  Linux Detective launcher - Powered by Bashar Salmo
#  Finds a Python 3 interpreter (including RHEL's platform-python), re-runs
#  itself with sudo when needed and passes every argument through, e.g.
#      ./linux-detective.sh --output /media/usb/Reports --case-id IR-2026-042
# =============================================================================
DIR=$(cd "$(dirname "$0")" && pwd)

PY=''
for c in python3 /usr/libexec/platform-python python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
        PY=$(command -v "$c"); break
    fi
done
if [ -z "$PY" ]; then
    echo "Linux Detective needs Python 3.6 or newer, and none was found on this system." >&2
    echo "Don't install it on a suspect machine: mount the disk read-only on a clean system and use --root instead." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "[*] Linux Detective needs root to read every system file - asking sudo..."
        exec sudo "$PY" -B "$DIR/linux_detective.py" "$@"
    fi
    echo "[!] Not root and sudo is not available - results will be incomplete." >&2
fi
exec "$PY" -B "$DIR/linux_detective.py" "$@"
