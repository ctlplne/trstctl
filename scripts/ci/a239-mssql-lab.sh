#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# A239 lab: the SQL Server (mssql) and Azure SQL (azure-sql, contained database
# users) dynamic-secret providers against SQL Server 2022 Developer Edition,
# mcr.microsoft.com/mssql/server 2022-CU27-ubuntu-22.04 (16.0.4295.3) pinned by
# digest. The image is x86_64 only, so this runs on an x86 Linux host: the
# ubuntu-latest CI job (owner decisions 2026-11-02). The Developer Edition's
# license terms are accepted here for this test use only (ACCEPT_EULA=Y,
# MSSQL_PID=Developer); the image is never shipped or redistributed.
#
# The lab: databases orders (dbo.orders, row 1), payments, and orders_contained
# (partial containment, dbo.orders, row 1) with contained database
# authentication on, and for A240's two-user rotation the logins orders_app_a
# and orders_app_b with users in orders that are db_datareader members. Every
# lab test must run and pass, no leased principal may be left behind, and the
# two logins must end enabled and still members.
set -euo pipefail
IMAGE=mcr.microsoft.com/mssql/server@sha256:4402d880dd4c34bfa7d8705e56a86cd6c88da80a1f6bbbe741f999e76264a090
NAME=trstctl-a239-mssql
if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "a239-mssql-lab: SQL Server's image is x86_64 Linux only; run this on an x86 Linux host (CI: ubuntu-latest)"
  exit 2
fi
lab="$(mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$lab"; }
trap cleanup EXIT
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
sa="Lab$(python3 -c 'import secrets; print(secrets.token_hex(16))')Aa1"
docker pull -q "$IMAGE" >/dev/null
docker run -d --name "$NAME" -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD="$sa" \
  -p "127.0.0.1:$port:1433" "$IMAGE" >/dev/null
sqlcmd() { docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -C -b -U sa -P "$sa" "$@"; }
ready=0
for _ in $(seq 1 90); do
  if sqlcmd -Q "SELECT 1" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "a239-mssql-lab: SQL Server did not start"; docker logs --tail 40 "$NAME"; exit 1; }
echo ">> $(sqlcmd -h -1 -W -Q "SET NOCOUNT ON; SELECT REPLACE(LEFT(@@VERSION, 60), CHAR(10), ' ')")"
sqlcmd -Q "EXEC sp_configure 'contained database authentication', 1; RECONFIGURE;" >/dev/null
sqlcmd -Q "CREATE DATABASE orders; CREATE DATABASE payments; CREATE DATABASE orders_contained CONTAINMENT = PARTIAL;"
for db in orders orders_contained; do
  sqlcmd -d "$db" -Q "CREATE TABLE dbo.orders (id int PRIMARY KEY); INSERT INTO dbo.orders (id) VALUES (1);" >/dev/null
done
app_a="Lab$(python3 -c 'import secrets; print(secrets.token_hex(16))')Aa1"
app_b="Lab$(python3 -c 'import secrets; print(secrets.token_hex(16))')Aa1"
sqlcmd -d orders -Q "CREATE LOGIN orders_app_a WITH PASSWORD = '$app_a', DEFAULT_DATABASE = orders; CREATE LOGIN orders_app_b WITH PASSWORD = '$app_b', DEFAULT_DATABASE = orders;
CREATE USER orders_app_a FOR LOGIN orders_app_a; CREATE USER orders_app_b FOR LOGIN orders_app_b;
ALTER ROLE db_datareader ADD MEMBER orders_app_a; ALTER ROLE db_datareader ADD MEMBER orders_app_b;" >/dev/null
umask 077
printf 'sqlserver://sa:%s@127.0.0.1:%s?database=master&encrypt=true&TrustServerCertificate=true\n' "$sa" "$port" > "$lab/dsn"
printf 'sqlserver://sa:%s@127.0.0.1:%s?database=orders_contained&encrypt=true&TrustServerCertificate=true\n' "$sa" "$port" > "$lab/contained-dsn"
echo ">> lab ready on 127.0.0.1:$port (orders, payments, orders_contained); the lab container's self-signed TLS certificate is trusted for this run only"
status=0
TRSTCTL_A239_MSSQL_DSN_FILE="$lab/dsn" TRSTCTL_A239_MSSQL_CONTAINED_DSN_FILE="$lab/contained-dsn" TRSTCTL_A239_MSSQL_CONTAINER="$NAME" \
TRSTCTL_A240_MSSQL_INITIAL_PASSWORD="$app_a" \
  go test -count=1 -timeout 25m -run '^(TestServedDynamic(SQLServerLogin|AzureSQLContainedUser)AgainstSQLServerA239|TestServedSQLServerTwoUserStaticRotationKeepsGrantsA240)$' -v ./internal/server/ \
  | tee "$lab/test.log" || status=$?
for test in TestServedDynamicSQLServerLoginAgainstSQLServerA239 TestServedDynamicAzureSQLContainedUserAgainstSQLServerA239 TestServedSQLServerTwoUserStaticRotationKeepsGrantsA240; do
  grep -q -- "--- PASS: $test " "$lab/test.log" || { echo "a239-mssql-lab: $test did not run and pass"; status=1; }
done
left="$(sqlcmd -h -1 -W -Q "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.server_principals WHERE name LIKE 'trstctl[_]%'")"
left_contained="$(sqlcmd -d orders_contained -h -1 -W -Q "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.database_principals WHERE name LIKE 'trstctl[_]%'")"
pair="$(sqlcmd -d orders -h -1 -W -Q "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.database_principals dp JOIN sys.server_principals sp ON sp.sid = dp.sid WHERE dp.name IN ('orders_app_a', 'orders_app_b') AND sp.is_disabled = 0 AND IS_ROLEMEMBER('db_datareader', dp.name) = 1")"
echo ">> leased logins left: $left; leased contained users left: $left_contained; two-user logins enabled and members: $pair"
[[ "$left" == 0 && "$left_contained" == 0 && "$pair" == 2 ]] || status=1
exit "$status"
