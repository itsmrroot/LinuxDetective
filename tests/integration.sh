#!/bin/sh
# =============================================================================
#  Linux Detective - live integration test (Powered by Bashar Salmo)
#  Plants a modified packaged binary, an unpackaged executable and an unpackaged
#  setuid file, runs the real CLI against the live system and checks that all
#  three are reported. It CHANGES SYSTEM FILES, so it only runs inside a
#  throwaway container:
#      podman run --rm -v "$PWD":/src:ro ubuntu:24.04 sh -c 'apt-get update && apt-get install -y python3 && sh /src/tests/integration.sh'
# =============================================================================
set -eu

if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
    echo "Refusing to run: this test modifies system files and is meant for throwaway containers only." >&2
    exit 2
fi
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
cp -r "$SRC" "$WORK/tool"
cd "$WORK/tool"

python3 -B -W error tests/test_core.py
python3 -B -W error tests/test_scan.py

# Plant the problems (whoami is packaged on every supported distro except busybox-based ones)
TARGET=/usr/bin/whoami
[ -L "$TARGET" ] && TARGET=/sbin/apk           # Alpine: whoami is a busybox symlink
printf 'x' >> "$TARGET"
cp /bin/true /usr/sbin/ld-integration-dropped
cp /bin/true /var/tmp/ld-integration-suid && chmod 4755 /var/tmp/ld-integration-suid
DROPPED=$(cd "$(readlink -f /usr/sbin)" && pwd)/ld-integration-dropped   # Arch: /usr/sbin -> /usr/bin

python3 -B linux_detective.py --output "$WORK/Reports" --case-id CI --no-archive > "$WORK/run.log" 2>&1 || {
    cat "$WORK/run.log"; exit 1; }
CASE=$(ls -d "$WORK"/Reports/LDCase_*)
F="$CASE/findings.json"

fail=0
check() {
    if python3 -c "import json,sys; f=json.load(open('$F')); sys.exit(0 if any(x['Title']==sys.argv[1] and ('path=%s ' % sys.argv[2]) in x['Evidence']+' ' for x in f) else 1)" "$1" "$2"; then
        echo "  PASS  $1: $2"
    else
        echo "  FAIL  $1: $2"; fail=1
    fi
}
echo "== $(. /etc/os-release; echo "$PRETTY_NAME") | python $(python3 -c 'import sys;print(sys.version.split()[0])')"
check 'Packaged system file has been modified' "$TARGET"
check 'Executable in a system directory is not owned by any package' "$DROPPED"
check 'Setuid / setgid file not owned by any package' /var/tmp/ld-integration-suid
grep -E 'Integrity:|Setuid / setgid inventory:|Collecting: Package|VERDICT' "$WORK/run.log" | sed 's/^/  /'
( cd "$CASE" && python3 - <<'EOF'
import csv, hashlib
bad = [r['File'] for r in csv.DictReader(open('manifest.sha256.csv')) if hashlib.sha256(open(r['File'], 'rb').read()).hexdigest() != r['SHA256']]
print('  PASS  manifest matches every file' if not bad else '  FAIL  manifest mismatch: %s' % bad)
raise SystemExit(1 if bad else 0)
EOF
) || fail=1
python3 -c "import json; f=json.load(open('$F')); [print('  finding: %-8s %s | %s' % (x['Severity'], x['Title'], x['Evidence'][:90])) for x in f if x['Severity'] in ('Critical','High','Medium')]"
exit $fail
