#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Real xrdp + FreeRDP + stock-viewer proof. Uses only an already-present approved
# Debian bookworm image; never pulls an image. Official lab apt packages are needed.
set -euo pipefail
: "${TRSTCTL_DESKTOP_LAB_BASE:?set an approved cached Debian bookworm image ID or repository@sha256 digest}"
case "$TRSTCTL_DESKTOP_LAB_BASE" in sha256:*|*@sha256:*) ;; *) echo 'a pinned image is required' >&2; exit 2;; esac
repo=$(cd "$(dirname "$0")/../.." && pwd)
proof=$(mktemp -d "${TMPDIR:-/tmp}/trstctl-desktop-proof.XXXXXX")
arch=$(docker image inspect --format '{{.Architecture}}' "$TRSTCTL_DESKTOP_LAB_BASE")
case "$arch" in arm64|amd64) ;; *) echo 'the native lab supports arm64 or amd64' >&2; exit 2;; esac
export GOPRIVATE='trstctl.com/*,github.com/ctlplne/*' GONOPROXY='trstctl.com/*,github.com/ctlplne/*' GONOSUMDB='trstctl.com/*,github.com/ctlplne/*'
cd "$repo"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$proof/server-test" ./internal/server
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$proof/rdp-test" ./internal/crypto/rdp
lab=$(docker run -d --pull=never --label trstctl.lab=desktop --cap-add IPC_LOCK --ulimit memlock=-1:-1 "$TRSTCTL_DESKTOP_LAB_BASE" sleep infinity)
printf '%s\n' "$lab" > "$proof/container.id"
cleanup() { docker stop "$lab" > "$proof/stop.log" 2>&1 || true; printf 'Evidence: %s\nStopped owned container: %s\n' "$proof" "$lab"; }
trap cleanup EXIT
# No password is an argument, environment variable, or retained test log.
docker exec "$lab" sh -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential pkg-config freerdp2-dev xrdp xorgxrdp xserver-xorg-core xterm xfonts-base xvfb tigervnc-viewer xdotool xclip openssh-server openssl ca-certificates postgresql-15
useradd -m -s /bin/bash desktop-proof
umask 077
openssl rand -hex 24 | tr -d "\n" > /run/rdp-password
{ printf "desktop-proof:"; cat /run/rdp-password; printf "\n"; } | chpasswd
openssl req -x509 -newkey rsa:2048 -nodes -keyout /run/rdp.key -out /run/rdp.crt -days 2 -subj /CN=localhost > /run/cert-build.log 2>&1
openssl x509 -in /run/rdp.crt -outform DER | openssl dgst -sha256 | awk "{print \$2}" > /run/rdp-pin
sed -i "s|^certificate=.*|certificate=/run/rdp.crt|;s|^key_file=.*|key_file=/run/rdp.key|;s|^security_layer=.*|security_layer=tls|;s|^allow_channels=.*|allow_channels=true|;s|^rdpdr=.*|rdpdr=false|;s|^rdpsnd=.*|rdpsnd=false|;s|^drdynvc=.*|drdynvc=false|;s|^cliprdr=.*|cliprdr=true|;s|^rail=.*|rail=false|;s|^xrdpvr=.*|xrdpvr=false|;s|^tcutils=.*|tcutils=false|" /etc/xrdp/xrdp.ini
# Each connection gets its own X session: tests never share an xterm, and no
# proof depends on reattaching a disconnected session.
sed -i "s|^Policy=.*|Policy=UBDC|" /etc/xrdp/sesman.ini
printf "#!/bin/sh\nexec /usr/bin/xterm -geometry 90x28+0+0 -bg navy -fg white\n" > /etc/xrdp/startwm.sh
chmod 755 /etc/xrdp/startwm.sh
mkdir -p /run/xrdp/sockdir /run/sshd /run/dbus
chmod 755 /run/xrdp /run/sshd /run/dbus
chmod 3777 /run/xrdp/sockdir
/usr/sbin/xrdp-sesman
/usr/sbin/xrdp
install -d -m 700 -o postgres -g postgres /var/lib/postgresql/desktop-lab
runuser -u postgres -- /usr/lib/postgresql/15/bin/initdb -D /var/lib/postgresql/desktop-lab -A trust
printf "listen_addresses = '\''127.0.0.1'\''\nport = 55432\nunix_socket_directories = '\'''\''\n" >> /var/lib/postgresql/desktop-lab/postgresql.conf
runuser -u postgres -- /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/desktop-lab -l /var/lib/postgresql/desktop-lab/server.log start
' > "$proof/setup.log" 2>&1
docker cp internal/crypto/rdp/native "$lab:/run/rdp-native"
docker cp "$proof/server-test" "$lab:/run/server-test"
docker cp "$proof/rdp-test" "$lab:/run/rdp-test"
docker exec "$lab" sh -c 'sh /run/rdp-native/build.sh /run/rdp-helper; /run/rdp-helper --check' > "$proof/native-build.log" 2>&1
docker exec -w /run "$lab" sh -c 'TRSTCTL_RDP_NATIVE_LAB=1 TRSTCTL_REQUIRE_RDP_LAB=1 /run/server-test -test.v -test.run "^(TestServedDesktopVaultedRegistrationA263|TestServedDesktopClipboardPolicyA269)\$" -test.timeout=5m' > "$proof/served.log" 2>&1
docker exec "$lab" sh -c 'TRSTCTL_REQUIRE_RDP_LAB=1 TRSTCTL_RDP_HELPER=/run/rdp-helper TRSTCTL_RDP_PIN=$(cat /run/rdp-pin) /run/rdp-test -test.v -test.run "^TestNative|^TestDesktop"' > "$proof/native.log" 2>&1
docker cp "$lab:/run/trstctl-desktop-export.json" "$proof/desktop-export.json"
docker exec "$lab" dpkg-query -W > "$proof/package-versions.tsv"
cat "$proof/served.log" "$proof/native.log"
