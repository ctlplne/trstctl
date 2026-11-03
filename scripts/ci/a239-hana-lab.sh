#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# A239 lab: the SAP HANA (hana) dynamic-secret provider against SAP HANA,
# express edition 2.00.088.00.20251110.1, saplabs/hanaexpress pinned by
# digest. The image is x86_64 only, so this runs on an x86 Linux host: the
# ubuntu-latest CI job (owner decision 2026-11-02, item 6). SAP's developer
# license is accepted here (--agree-to-sap-license) for this test use only;
# the image is never shipped or redistributed. The script measures the
# runner's memory and disk and the database's own footprint, so a run that
# cannot fit records why.
#
# The lab, in tenant HXE: administrator LAB_ADMIN (USER ADMIN, SESSION ADMIN,
# CATALOG READ, ORDERS_READER WITH ADMIN OPTION), role ORDERS_READER (SELECT on
# schema ORDERS), tables ORDERS.ITEMS and BILLING.INVOICES with one row each.
# The lab test must run and pass, and no leased user may be left behind.
set -euo pipefail
IMAGE=saplabs/hanaexpress@sha256:432be2785506e97cefc413f495393fc22fcdda034c2c80db2f0f88efeb16dfaf
NAME=trstctl-a239-hana
if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "a239-hana-lab: SAP HANA, express edition's image is x86_64 Linux only; run this on an x86 Linux host (CI: ubuntu-latest)"
  exit 2
fi
echo ">> runner: $(nproc) CPUs, $(free -g | awk '/^Mem:/ {print $2 " GiB memory, " $7 " GiB available"}'), $(df -h --output=avail / | tail -1 | tr -d ' ') free on /"
lab="$(mktemp -d)"
cleanup() {
  docker logs --tail 40 "$NAME" > "$lab/hana-tail.log" 2>&1 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  sudo rm -rf "$lab"
}
trap cleanup EXIT
master="Lab$(python3 -c 'import secrets; print(secrets.token_hex(12))')Aa1"
admin="Lab$(python3 -c 'import secrets; print(secrets.token_hex(12))')Aa1"
mkdir -p "$lab/mounts"
printf '{"master_password" : "%s"}\n' "$master" > "$lab/mounts/password.json"
sudo chown -R 12000:79 "$lab/mounts"
sudo chmod 700 "$lab/mounts"
sudo chmod 600 "$lab/mounts/password.json"
start=$(date +%s)
docker pull -q "$IMAGE" >/dev/null
echo ">> image pulled in $(( $(date +%s) - start ))s: $(docker image inspect "$IMAGE" --format '{{.Size}}') bytes"
docker run -d --name "$NAME" -p 127.0.0.1:39041:39041 -v "$lab/mounts:/hana/mounts" \
  --ulimit nofile=1048576:1048576 \
  --sysctl kernel.shmmax=1073741824 --sysctl net.ipv4.ip_local_port_range='40000 60999' \
  --sysctl kernel.shmmni=4096 --sysctl kernel.shmall=8388608 \
  "$IMAGE" --passwords-url file:///hana/mounts/password.json --agree-to-sap-license >/dev/null
start=$(date +%s)
ready=0
for _ in $(seq 1 240); do
  if docker logs "$NAME" 2>&1 | grep -q "Startup finished"; then ready=1; break; fi
  if ! docker ps -q -f "name=^${NAME}$" | grep -q .; then break; fi
  sleep 5
done
echo ">> database start: ready=$ready after $(( $(date +%s) - start ))s; container memory $(docker stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null || echo n/a); $(df -h --output=avail / | tail -1 | tr -d ' ') free on /"
if [[ "$ready" != 1 ]]; then
  echo "a239-hana-lab: SAP HANA, express edition did not start on this runner"
  docker logs --tail 60 "$NAME" || true
  exit 1
fi
hdbsql() { docker exec "$NAME" /usr/sap/HXE/HDB90/exe/hdbsql -i 90 -d HXE -u SYSTEM -p "$master" -x -a "$@"; }
for statement in \
  "CREATE SCHEMA ORDERS" \
  "CREATE COLUMN TABLE ORDERS.ITEMS (ID NVARCHAR(40) PRIMARY KEY)" \
  "INSERT INTO ORDERS.ITEMS VALUES ('order-1')" \
  "CREATE SCHEMA BILLING" \
  "CREATE COLUMN TABLE BILLING.INVOICES (ID NVARCHAR(40) PRIMARY KEY)" \
  "INSERT INTO BILLING.INVOICES VALUES ('invoice-1')" \
  "CREATE ROLE ORDERS_READER" \
  "GRANT SELECT ON SCHEMA ORDERS TO ORDERS_READER" \
  "CREATE USER LAB_ADMIN PASSWORD \"$admin\" NO FORCE_FIRST_PASSWORD_CHANGE" \
  "ALTER USER LAB_ADMIN DISABLE PASSWORD LIFETIME" \
  "GRANT USER ADMIN, SESSION ADMIN, CATALOG READ TO LAB_ADMIN" \
  "GRANT ORDERS_READER TO LAB_ADMIN WITH ADMIN OPTION"; do
  hdbsql "$statement" >/dev/null || { echo "a239-hana-lab: lab setup failed at: ${statement%% PASSWORD*}"; exit 1; }
done
echo ">> $(hdbsql "SELECT VERSION FROM SYS.M_DATABASE" | tr -d '"')"
umask 077
printf 'hdb://LAB_ADMIN:%s@127.0.0.1:39041\n' "$admin" > "$lab/admin-dsn"
status=0
TRSTCTL_A239_HANA_ADMIN_DSN_FILE="$lab/admin-dsn" TRSTCTL_A239_HANA_CONTAINER="$NAME" \
  go test -count=1 -timeout 15m -run '^TestServedDynamicHANAUserAgainstHANAExpressA239$' -v ./internal/server/ \
  | tee "$lab/test.log" || status=$?
grep -q -- "--- PASS: TestServedDynamicHANAUserAgainstHANAExpressA239 " "$lab/test.log" || { echo "a239-hana-lab: the lab test did not run and pass"; status=1; }
left="$(hdbsql "SELECT COUNT(*) FROM SYS.USERS WHERE USER_NAME LIKE 'TRSTCTL\_%' ESCAPE '\\'" | tr -d ' "')"
echo ">> leased users left: $left; peak container memory $(docker stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null || echo n/a)"
[[ "$left" == 0 ]] || status=1
exit "$status"
