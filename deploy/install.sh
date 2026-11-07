#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf '%s\n' 'Usage: sudo /bin/sh deploy/install.sh CONFIG.json' >&2
    exit 2
fi

config=$1
source=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target='/Library/Application Support/PSRemotePlayRelay'
log_dir='/Library/Logs/PSRemotePlayRelay'
label=local.ps-remote-play-relay
plist="/Library/LaunchDaemons/$label.plist"

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

/usr/bin/install -d -o root -g wheel -m 0755 "$stage/psrp" "$log_dir"
for name in __init__ __main__ macos wire; do
    /usr/bin/install -o root -g wheel -m 0644 "$source/psrp/$name.py" "$stage/psrp/$name.py"
done
/usr/bin/install -o root -g wheel -m 0600 "$config" "$stage/config.json"
/usr/bin/plutil -lint "$source/deploy/$label.plist"
(cd "$stage" && /usr/bin/python3 -E -s -B -m psrp --check)

/bin/mv "$stage" "$target"
installed=yes
plist_created=yes
/usr/bin/install -o root -g wheel -m 0644 "$source/deploy/$label.plist" "$plist"
/bin/launchctl bootstrap system "$plist"
loaded=yes
/bin/launchctl print "system/$label" | /usr/bin/awk '/state =|pid =/'
