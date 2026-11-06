#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Uses two approved cached images. No pulls, published ports or existing domains.
set -euo pipefail
: "${TRSTCTL_AD_LAB_BASE:?set an approved cached Samba image ID or repository@sha256 digest}"
: "${TRSTCTL_AD_CLIENT_BASE:?set an approved cached Debian bookworm image ID or repository@sha256 digest}"
for base in "$TRSTCTL_AD_LAB_BASE" "$TRSTCTL_AD_CLIENT_BASE"; do
 case "$base" in sha256:*|*@sha256:*) ;; *) echo 'pinned cached images required' >&2; exit 2;; esac
 docker image inspect "$base" >/dev/null
done
repo=$(cd "$(dirname "$0")/../.." && pwd)
proof=$(mktemp -d "${TMPDIR:-/tmp}/trstctl-ad-proof.XXXXXX")
arch=$(docker image inspect --format '{{.Architecture}}' "$TRSTCTL_AD_CLIENT_BASE")
case "$arch" in arm64|amd64) ;; *) echo 'unsupported client architecture' >&2; exit 2;; esac
export GOPRIVATE='trstctl.com/*,github.com/ctlplne/*' GONOPROXY='trstctl.com/*,github.com/ctlplne/*' GONOSUMDB='trstctl.com/*,github.com/ctlplne/*'
cd "$repo"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$proof/dynsecret-test" ./internal/dynsecret
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$proof/server-test" ./internal/server
network=$(docker network create --label trstctl.lab=ad "$(basename "$proof")")
dc='' client=''
cleanup() {
 for id in "$client" "$dc"; do if [ -n "$id" ]; then docker stop "$id" >> "$proof/stop.log" 2>&1 || true; fi; done
 printf 'Evidence: %s\nStopped owned client: %s\nStopped owned DC: %s\nRetained owned network: %s\n' "$proof" "$client" "$dc" "$network"
}
trap cleanup EXIT
dc=$(docker run -d --pull=never --label trstctl.lab=ad --hostname ad263 --network "$network" --network-alias ad263 --entrypoint /bin/sh "$TRSTCTL_AD_LAB_BASE" -c 'sleep infinity')
printf '%s\n' "$dc" > "$proof/dc.id"
docker cp scripts/labs/active-directory/provision.py "$dc:/run/provision.py"
docker exec "$dc" sh -c '
set -eu
umask 077
{ printf "Tr5!"; openssl rand -hex 32 | tr -d "\n"; } > /run/ad-admin-password
python3 /run/provision.py > /run/provision.log 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout /run/ad-key.pem -out /run/ad-cert.pem -days 3 -subj /CN=ad263 -addext subjectAltName=DNS:ad263 > /run/cert.log 2>&1
cfg=/var/lib/trstctl-ad/etc/smb.conf
printf "\n[global]\n tls enabled = yes\n tls keyfile = /run/ad-key.pem\n tls certfile = /run/ad-cert.pem\n tls cafile = /run/ad-cert.pem\n ldap server require strong auth = yes\n" >> "$cfg"
samba-tool ou create OU=TrstctlA263,DC=a263,DC=test -s "$cfg" > /run/seed.log 2>&1
samba-tool user create a263-proof --userou=OU=TrstctlA263 -s "$cfg" --random-password >> /run/seed.log 2>&1
samba-tool user create a263-served --userou=OU=TrstctlA263 -s "$cfg" --random-password >> /run/seed.log 2>&1
samba-tool domain passwordsettings set --account-lockout-threshold=3 -s "$cfg" >> /run/seed.log 2>&1
samba -D --no-process-group -s "$cfg"
' > "$proof/setup-dc.log" 2>&1
client=$(docker run -d --pull=never --label trstctl.lab=ad --network "$network" "$TRSTCTL_AD_CLIENT_BASE" sleep infinity)
printf '%s\n' "$client" > "$proof/client.id"
docker exec "$client" sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends ldap-utils ca-certificates postgresql-15' > "$proof/setup-client.log" 2>&1
umask 077
docker cp "$dc:/run/ad-admin-password" "$proof/admin-password"
chmod 600 "$proof/admin-password"
docker cp "$dc:/run/ad-cert.pem" "$proof/ad-ca.pem"
docker cp "$proof/admin-password" "$client:/run/ad-admin-password"
rm -f "$proof/admin-password"
docker cp "$proof/ad-ca.pem" "$client:/run/ad-ca.pem"
docker cp "$proof/dynsecret-test" "$client:/run/dynsecret-test"
docker cp "$proof/server-test" "$client:/run/server-test"
docker cp scripts/labs/active-directory/client-setup.sh "$client:/run/client-setup.sh"
docker exec "$client" sh /run/client-setup.sh > "$proof/postgres-setup.log" 2>&1
docker exec "$client" sh -c '
set -eu
chmod 600 /run/ad-admin-password
ready=false
for attempt in $(seq 1 60); do
 if LDAPTLS_CACERT=/run/ad-ca.pem timeout 2 ldapsearch -LLL -x -H ldaps://ad263:636 -D CN=Administrator,CN=Users,DC=a263,DC=test -y /run/ad-admin-password -b "" -s base defaultNamingContext > /run/ready.log 2>&1; then ready=true; break; fi
 sleep 0.25
done
$ready
TRSTCTL_AD_NATIVE_LAB=1 /run/dynsecret-test -test.v -test.run ^TestActiveDirectoryVaultedPasswordNativeA263$ -test.timeout=60s
' > "$proof/native.log" 2>&1
docker exec -w /run "$client" sh -c 'TRSTCTL_AD_SERVED_LAB=1 /run/server-test -test.v -test.run ^TestServedADAccountRotationA263$ -test.timeout=90s' > "$proof/served.log" 2>&1
docker exec "$dc" sh -c 'samba --version; samba-tool domain passwordsettings show -s /var/lib/trstctl-ad/etc/smb.conf; testparm -s /var/lib/trstctl-ad/etc/smb.conf --parameter-name="old password allowed period" 2>/dev/null' > "$proof/directory-version-policy.txt"
docker exec "$client" dpkg-query -W > "$proof/client-packages.tsv"
cat "$proof/native.log" "$proof/served.log"
