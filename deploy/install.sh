#!/bin/sh
set -eu

if [ "$#" -gt 2 ] || [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf '%s\n' 'Usage: sudo /bin/sh deploy/install.sh [CONFIG.toml [ABSOLUTE_PYTHON]]' >&2
    exit 2
fi

config=${1:-config.toml}
source=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target='/Library/Application Support/PSBitrateRelay'
log_dir='/Library/Logs/PSBitrateRelay'
label=local.ps-bitrate-relay
plist="/Library/LaunchDaemons/$label.plist"
template="$source/deploy/$label.plist"
python=${2:-$(/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$template")}

case "$config" in
    *.toml) ;;
    *) printf '%s\n' 'Expected a .toml configuration file.' >&2; exit 2 ;;
esac
case "$python" in
    /*) ;;
    *) printf '%s\n' 'Python interpreter must be an absolute path.' >&2; exit 2 ;;
esac
if [ ! -x "$python" ] || ! "$python" -I -B -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    printf 'Python 3.11 or newer is required: %s\n' "$python" >&2
    exit 2
fi

if [ -e "$target" ] || [ -e "$plist" ] || /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    printf '%s\n' 'The relay already has an installation. Stop the installed service before updating.' >&2
    exit 1
fi

stage=$(/usr/bin/mktemp -d '/Library/Application Support/.psrp.XXXXXXXX')
installed=no
plist_created=no
loaded=no
cleanup() {
    /bin/rm -rf -- "$stage"
    if [ "$loaded" = no ]; then
        if [ "$plist_created" = yes ]; then /bin/rm -f -- "$plist"; fi
        if [ "$installed" = yes ]; then /bin/rm -rf -- "$target"; fi
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

/usr/bin/install -d -o root -g wheel -m 0755 "$stage/ps_bitrate_relay" "$log_dir"
for name in __init__ __main__ config macos wire; do
    /usr/bin/install -o root -g wheel -m 0644 "$source/ps_bitrate_relay/$name.py" "$stage/ps_bitrate_relay/$name.py"
done
/usr/bin/install -o root -g wheel -m 0600 "$config" "$stage/config.toml"
"$python" -I -B - "$template" "$stage/$label.plist" "$python" "$target/config.toml" <<'PY'
import plistlib
import sys

template, destination, interpreter, config = sys.argv[1:]
with open(template, "rb") as source:
    job = plistlib.load(source)
job["ProgramArguments"][0] = interpreter
job["ProgramArguments"][-1] = config
with open(destination, "wb") as output:
    plistlib.dump(job, output)
PY
/usr/bin/plutil -lint "$stage/$label.plist"
(cd "$stage" && "$python" -E -s -B -m ps_bitrate_relay --config config.toml --check)

/bin/mv "$stage" "$target"
installed=yes
plist_created=yes
/usr/bin/install -o root -g wheel -m 0644 "$target/$label.plist" "$plist"
/bin/rm -- "$target/$label.plist"
/bin/launchctl bootstrap system "$plist"
loaded=yes
/bin/launchctl print "system/$label" | /usr/bin/awk '/state =|pid =/'
