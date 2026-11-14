#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# A239-L2 lab: runs the dynsecret proof that a lease's directory entry expires
# in the directory itself (TestLDAPDynamicLeaseExpiresInOpenLDAPA239L2) against
# stock OpenLDAP 2.6 with its dds overlay. The image is built from an approved
# cached Alpine 3.20 image (never pulled) and Alpine's own packages; the
# directory listens on loopback only; the administrator password is random,
# kept in a private temp directory only while the proof runs, never printed.
set -euo pipefail
: "${TRSTCTL_LDAP_DDS_BASE:?set an approved cached Alpine 3.20 image ID or repository@sha256 digest}"
case "$TRSTCTL_LDAP_DDS_BASE" in sha256:*|*@sha256:*) ;; *) echo 'a pinned cached image is required' >&2; exit 2;; esac
docker image inspect "$TRSTCTL_LDAP_DDS_BASE" >/dev/null
repo=$(cd "$(dirname "$0")/../.." && pwd)
proof=$(mktemp -d "${TMPDIR:-/tmp}/trstctl-ldap-dds.XXXXXX")
chmod 700 "$proof"
image=trstctl-lab-openldap-dds:local
docker build --pull=false --build-arg "BASE=$TRSTCTL_LDAP_DDS_BASE" -t "$image" "$repo/scripts/labs/openldap-dds" > "$proof/build.log" 2>&1
lab=''
trap 'if [ -n "$lab" ]; then docker rm -f "$lab" > /dev/null 2>&1 || true; fi; rm -f "$proof/admin-password"; printf "Evidence: %s\n" "$proof"' EXIT
(umask 077; python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_hex(16))' > "$proof/admin-password")
lab=$(docker run -d --rm --label trstctl.lab=openldap-dds -p 127.0.0.1::389 "$image")
docker cp "$proof/admin-password" "$lab:/run/admin-pw"
docker exec "$lab" sh -c 'chmod 600 /run/admin-pw && /usr/local/bin/trstctl-ldap-dds-setup.sh'
docker exec "$lab" apk list --installed 2>/dev/null | grep -E '^openldap' | tee "$proof/packages.txt"
port=$(docker port "$lab" 389/tcp | head -1 | sed 's/.*://')
echo "OpenLDAP with dds on 127.0.0.1:$port"
cd "$repo"
TRSTCTL_LDAP_DDS_LAB=1 TRSTCTL_LDAP_DDS_ADDR="127.0.0.1:$port" TRSTCTL_LDAP_DDS_ADMIN="$proof/admin-password" \
  go test -count=1 -v -run 'TestLDAPDynamicLeaseExpiresInOpenLDAPA239L2$' ./internal/dynsecret/ | tee "$proof/test.log"
grep -q '^--- PASS: TestLDAPDynamicLeaseExpiresInOpenLDAPA239L2' "$proof/test.log"
