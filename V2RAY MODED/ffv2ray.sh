#!/usr/bin/env bash
# visibleTech V2Ray (Xray) - shell launcher
# Downloads ffv2ray.py (+ the web panel files) from GitHub and starts the installer / manager.
#
#   bash <(curl -fsSL "https://raw.githubusercontent.com/wavy07/Script4/main/V2RAY%20MODED/ffv2ray.sh")
#
# Any argument is passed to ffv2ray.py:   bash ffv2ray.sh panel | status | list ...
# Environment: FFV2_REPO_BASE (download folder URL), FFV2_HOME (where the files are kept, default /opt/visibleTech)

REPO_BASE="${FFV2_REPO_BASE:-https://raw.githubusercontent.com/wavy07/Script4/main/V2RAY%20MODED}"
HOME_DIR="${FFV2_HOME:-/opt/visibleTech}"
FILES="ffv2ray.py ffv2panel.py ffv2panel.html"

die() { echo "Error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (sudo bash ffv2ray.sh)"

# python3 + curl
if ! have python3 || ! have curl; then
    echo "Installing python3 and curl..."
    if have apt-get; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1
        apt-get install -y python3 curl >/dev/null 2>&1 || die "could not install python3 / curl"
    elif have dnf; then
        dnf install -y python3 curl >/dev/null 2>&1 || die "could not install python3 / curl"
    elif have yum; then
        yum install -y python3 curl >/dev/null 2>&1 || die "could not install python3 / curl"
    else
        die "install python3 and curl first"
    fi
fi

mkdir -p "$HOME_DIR" || die "cannot create $HOME_DIR"
cd "$HOME_DIR" || die "cannot enter $HOME_DIR"

# download the files; an older copy is kept when a download fails
for f in $FILES; do
    if curl -fsSL --retry 3 --connect-timeout 15 "$REPO_BASE/$f" -o "$f.new" && [ -s "$f.new" ]; then
        mv -f "$f.new" "$f"
    else
        rm -f "$f.new"
        if [ -f "$f" ]; then
            echo "Could not download $f - using the copy already here."
        elif [ "$f" = "ffv2ray.py" ]; then
            die "could not download ffv2ray.py from $REPO_BASE"
        else
            echo "Could not download $f (the web panel will not be available)."
        fi
    fi
done
chmod 755 ffv2ray.py ffv2panel.py 2>/dev/null

exec python3 "$HOME_DIR/ffv2ray.py" "$@"
