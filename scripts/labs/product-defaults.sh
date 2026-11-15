#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# X2-L7 lab: stock HAProxy and OpenSSL from Alpine's own packages in a throwaway container on
# loopback (an approved cached Alpine image, never pulled; apk fetches the packages), each serving
# TLS with its packaged defaults: a HAProxy listener that states no minimum or curves, and
# openssl s_server with the packaged openssl.cnf. The host scan reads the container's
# haproxy.cfg, openssl.cnf and apk database and claims each default; the endpoint scan then
# measures each listener (its lowest accepted version, and whether it takes X25519MLKEM768), and
# the two must agree (TestHostDefaultsAgreeWithTheEndpointScanX2L7Lab).
set -euo pipefail
: "${TRSTCTL_X2L7_BASE:?set an approved cached Alpine image ID or repository@sha256 digest}"
case "$TRSTCTL_X2L7_BASE" in sha256:*|*@sha256:*) ;; *) echo 'a pinned cached image is required' >&2; exit 2;; esac
docker image inspect "$TRSTCTL_X2L7_BASE" > /dev/null
repo=$(cd "$(dirname "$0")/../.." && pwd)
proof=$(mktemp -d "${TRSTCTL_LAB_EVIDENCE:-${TMPDIR:-/tmp}}/trstctl-product-defaults.XXXXXX")
lab=''
trap 'if [ -n "$lab" ]; then docker rm -f "$lab" > /dev/null 2>&1 || true; fi; printf "Evidence: %s\n" "$proof"' EXIT
lab=$(docker run -d --rm --pull never --label trstctl.lab=product-defaults -p 127.0.0.1::8443 -p 127.0.0.1::9443 "$TRSTCTL_X2L7_BASE" sleep 900)
docker exec "$lab" sh -c 'apk add --no-cache haproxy openssl > /dev/null && apk list --installed 2> /dev/null | grep -E "^(haproxy|libssl3|openssl)-"' | tee "$proof/packages.txt"
docker exec "$lab" sh -c '
set -e
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout key.pem -out cert.pem -days 1 -subj /CN=lab.test 2> /dev/null
cat cert.pem key.pem > site.pem
printf "%s\n" "global" "  log stdout format raw local0" "defaults" "  mode http" "  timeout connect 5s" "  timeout client 30s" \
  "  timeout server 30s" "frontend web" "  bind :8443 ssl crt /tmp/site.pem" "  http-request return status 200 content-type text/plain string ok" \
  > /etc/haproxy/haproxy.cfg
haproxy -D -f /etc/haproxy/haproxy.cfg
nohup sh -c "sleep 900 | openssl s_server -quiet -accept 9443 -cert /tmp/cert.pem -key /tmp/key.pem -www" > /tmp/s_server.log 2>&1 &
'
docker cp "$lab:/etc/haproxy/haproxy.cfg" "$proof/haproxy.cfg"
docker cp "$lab:/etc/ssl/openssl.cnf" "$proof/openssl.cnf"
docker cp "$lab:/lib/apk/db/installed" "$proof/installed"
hap=$(docker port "$lab" 8443/tcp | head -1 | sed 's/.*://')
ossl=$(docker port "$lab" 9443/tcp | head -1 | sed 's/.*://')
for _ in $(seq 1 30); do (exec 3<> "/dev/tcp/127.0.0.1/$ossl") 2> /dev/null && break; sleep 0.5; done
echo "HAProxy on 127.0.0.1:$hap, openssl s_server on 127.0.0.1:$ossl"
cd "$repo"
TRSTCTL_X2L7_LAB_DIR="$proof" TRSTCTL_X2L7_HAPROXY_ADDR="127.0.0.1:$hap" TRSTCTL_X2L7_OPENSSL_ADDR="127.0.0.1:$ossl" \
  go test -count=1 -v -run '^TestHostDefaultsAgreeWithTheEndpointScanX2L7Lab$' ./internal/cbom/hostsource/ | tee "$proof/test.log"
grep -q '^--- PASS: TestHostDefaultsAgreeWithTheEndpointScanX2L7Lab ' "$proof/test.log"
