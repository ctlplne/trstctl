#!/usr/bin/env bash
# restore-rehearsal.sh — OPS-RESTORE-001: prove the shipped binary's full DR
# story end-to-end, every run:
#
#   populated instance A ──--full-backup-dir──▶ artifact dir
#        │                                          │
#        ▼                                          ▼
#   (stopped)                fresh instance B ◀──--full-restore-dir
#                                     │
#                                     ▼
#                    boots healthy, old data readable, NEW issuance works
#
# and the control: a deliberately CORRUPTED backup must make the restore fail
# closed (non-zero) rather than boot a silently-wrong control plane.
#
# Self-contained: digest-pinned external PostgreSQL + NATS containers, TLS
# disabled on loopback (rehearsal only). Full DR intentionally rejects bundled
# datastores because their process lifecycle is owned by the control plane.
# Requires: go toolchain, Docker, curl, jq, python3.
set -euo pipefail

say() { printf '>> restore-rehearsal: %s\n' "$*"; }
fail() { printf '::error::restore-rehearsal: %s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trstctl-restore-rehearsal.XXXXXX")"
SERVER_PID=""
INFRA_IDS=""
cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
	for id in $INFRA_IDS; do docker rm -f "$id" >/dev/null 2>&1 || true; done
	rm -rf "$ROOT"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

BIN_DIR="$ROOT/bin"
mkdir -p "$BIN_DIR"
if [ -n "${TRSTCTL_REHEARSAL_BIN:-}" ]; then
	cp "$TRSTCTL_REHEARSAL_BIN/trstctl" "$TRSTCTL_REHEARSAL_BIN/trstctl-signer" "$BIN_DIR/"
else
	say "building shipped binaries"
	(cd "$REPO_ROOT" && go build -o "$BIN_DIR/trstctl" ./cmd/trstctl && go build -o "$BIN_DIR/trstctl-signer" ./cmd/trstctl-signer)
fi
BIN="$BIN_DIR/trstctl"

command -v docker >/dev/null 2>&1 || fail "Docker is required for fresh external PostgreSQL/NATS datastores"
POSTGRES_IMAGE="postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
NATS_IMAGE="nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927"
POSTGRES_PASSWORD="trstctl-dr-rehearsal-password"

wait_postgres() { # $1 = container id
	local id="$1"
	for _ in $(seq 1 60); do
		if docker exec "$id" pg_isready -U postgres -d postgres >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	docker logs "$id" >&2 || true
	fail "external PostgreSQL did not become ready"
}

wait_tcp() { # $1 = loopback port, $2 = label
	local port="$1" label="$2"
	for _ in $(seq 1 60); do
		if python3 - "$port" <<'PY'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5):
        pass
except OSError:
    raise SystemExit(1)
PY
		then return 0; fi
		sleep 1
	done
	fail "$label did not become ready on 127.0.0.1:$port"
}

start_infra() { # $1 = PostgreSQL loopback port, $2 = NATS loopback port
	local pgport="$1" natsport="$2" pgid natsid
	pgid="$(docker run -d --rm \
		-e "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
		-p "127.0.0.1:$pgport:5432" "$POSTGRES_IMAGE")" \
		|| fail "start external PostgreSQL container"
	INFRA_IDS="$INFRA_IDS $pgid"
	natsid="$(docker run -d --rm \
		-p "127.0.0.1:$natsport:4222" "$NATS_IMAGE" -js -sd /data)" \
		|| fail "start external NATS container"
	INFRA_IDS="$INFRA_IDS $natsid"
	wait_postgres "$pgid"
	wait_tcp "$natsport" "external NATS"
}

write_config() { # $1 = instance dir, $2 = server port, $3 = pg port, $4 = NATS port
	local dir="$1" port="$2" pgport="$3" natsport="$4"
	mkdir -p "$dir"
	cat > "$dir/config.json" <<EOF
{
  "server": {"addr": "127.0.0.1:$port", "tls": {"mode": "disabled", "allow_plaintext_dev": true}},
  "postgres": {"mode": "external", "dsn": "postgres://postgres:$POSTGRES_PASSWORD@127.0.0.1:$pgport/postgres?sslmode=disable"},
  "nats": {"mode": "external", "url": "nats://127.0.0.1:$natsport", "replicas": 1, "allow_single_replica": true},
  "migrate": {"auto": true},
  "rate_limit": {"enabled": false},
  "telemetry": {"enabled": false},
  "audit": {"signing_key_file": "$dir/audit-signing-key.pem"},
  "secrets": {"enable_api": true, "kek_file": "$dir/secrets-kek.bin"},
  "signer": {"socket": "$dir/signer.sock", "key_store_dir": "$dir/signer-keys", "auth_secret_file": "$dir/signer-auth.bin", "allow_insecure_dev_nonlinux": true},
  "ca": {"cert_file": "$dir/issuing-ca.pem"}
}
EOF
	printf '%s' "$dir/config.json"
}

run_bin() { # $1 = config file, rest = args
	local cfg="$1"; shift
	env TRSTCTL_CONFIG_FILE="$cfg" "$BIN" "$@"
}

start_server() { # $1 = config file, $2 = log file
	env TRSTCTL_CONFIG_FILE="$1" "$BIN" >"$2" 2>&1 &
	SERVER_PID=$!
}

wait_ready() { # $1 = base url, $2 = log file
	for _ in $(seq 1 120); do
		if curl -fsS -o /dev/null "$1/readyz" 2>/dev/null; then return 0; fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			tail -40 "$2" >&2 || true
			fail "control plane exited before becoming ready"
		fi
		sleep 1
	done
	tail -40 "$2" >&2 || true
	fail "control plane did not become ready within 120s"
}

stop_server() {
	kill "$SERVER_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
	SERVER_PID=""
}

post() { # $1 = base, $2 = token, $3 = idem key, $4 = path, $5 = body
	curl -fsS -H "Authorization: Bearer $2" -H "Idempotency-Key: $3" \
		-H "Content-Type: application/json" -XPOST "$1$4" -d "$5"
}

# ---------------------------------------------------------------- instance A
A_PORT="$(free_port)"; A_PG="$(free_port)"; A_NATS="$(free_port)"
start_infra "$A_PG" "$A_NATS"
A_CFG="$(write_config "$ROOT/a" "$A_PORT" "$A_PG" "$A_NATS")"
A_URL="http://127.0.0.1:$A_PORT"
TENANT="00000000-0000-4000-8000-0000000d0d01"

say "instance A: first-run bootstrap token"
TOKEN="$(run_bin "$A_CFG" token create --tenant "$TENANT" --tenant-name "DR rehearsal" \
	--subject rehearsal-operator \
	--scopes owners:read,owners:write,issuers:read,issuers:write,identities:read,identities:write,certs:read,certs:request,certs:issue \
	| tail -1)"
[ -n "$TOKEN" ] || fail "token create produced nothing"

say "instance A: boot + seed (owner -> issuer -> identity -> issued cert)"
start_server "$A_CFG" "$ROOT/a.log"
wait_ready "$A_URL" "$ROOT/a.log"

OWNER="$(post "$A_URL" "$TOKEN" rehearsal-owner /api/v1/owners '{"kind":"workload","name":"dr-rehearsal"}' | jq -r .id)"
[ -n "$OWNER" ] && [ "$OWNER" != "null" ] || fail "owner create failed"
ISSUER="$(post "$A_URL" "$TOKEN" rehearsal-issuer /api/v1/issuers \
	'{"kind":"x509_ca","name":"dr-ca","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}' | jq -r .id)"
[ -n "$ISSUER" ] && [ "$ISSUER" != "null" ] || fail "issuer create failed"
IDENT="$(post "$A_URL" "$TOKEN" rehearsal-ident /api/v1/identities \
	"{\"kind\":\"x509_certificate\",\"name\":\"dr-rehearsal.example\",\"owner_id\":\"$OWNER\",\"issuer_id\":\"$ISSUER\"}" | jq -r .id)"
[ -n "$IDENT" ] && [ "$IDENT" != "null" ] || fail "identity create failed"
post "$A_URL" "$TOKEN" rehearsal-issue "/api/v1/identities/$IDENT/transitions" '{"to":"issued"}' >/dev/null || fail "issue transition failed"
CERTS=0
for _ in $(seq 1 30); do
	CERTS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$A_URL/api/v1/certificates" | jq '[.items[]? | select((.subject // "") | contains("dr-rehearsal.example"))] | length')"
	[ "${CERTS:-0}" -ge 1 ] && break
	sleep 1
done
[ "${CERTS:-0}" -ge 1 ] || fail "instance A minted no certificate within SLA"
say "instance A seeded (owner=$OWNER cert(s)=$CERTS)"
stop_server

# ---------------------------------------------------------------- backup
BACKUP="$ROOT/backup"
KEYFILE="$ROOT/backup.key"
head -c 32 /dev/urandom > "$KEYFILE"
say "full backup from A"
run_bin "$A_CFG" --full-backup-dir "$BACKUP" --backup-encryption-key-file "$KEYFILE" \
	|| fail "--full-backup-dir failed"
[ -d "$BACKUP" ] || fail "backup directory was not created"

# ---------------------------------------------------------------- restore -> B
B_PORT="$(free_port)"; B_PG="$(free_port)"; B_NATS="$(free_port)"
start_infra "$B_PG" "$B_NATS"
B_CFG="$(write_config "$ROOT/b" "$B_PORT" "$B_PG" "$B_NATS")"
B_URL="http://127.0.0.1:$B_PORT"
say "restore independently-held deployment KEK into instance B"
[ -s "$ROOT/a/secrets-kek.bin" ] || fail "instance A deployment KEK is missing"
install -m 0600 "$ROOT/a/secrets-kek.bin" "$ROOT/b/secrets-kek.bin"
say "full restore into fresh instance B"
run_bin "$B_CFG" --full-restore-dir "$BACKUP" --backup-encryption-key-file "$KEYFILE" \
	|| fail "--full-restore-dir failed on a GOOD backup"

say "instance B: boot + verify restored data + NEW issuance"
start_server "$B_CFG" "$ROOT/b.log"
wait_ready "$B_URL" "$ROOT/b.log"
curl -fsS -H "Authorization: Bearer $TOKEN" "$B_URL/api/v1/owners/$OWNER" >/dev/null \
	|| fail "restored instance cannot read back owner $OWNER"
RESTORED_CERTS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$B_URL/api/v1/certificates" | jq '[.items[]? | select((.subject // "") | contains("dr-rehearsal.example"))] | length')"
[ "${RESTORED_CERTS:-0}" -ge 1 ] || fail "restored instance lost the issued certificate"
IDENT2="$(post "$B_URL" "$TOKEN" rehearsal-ident2 /api/v1/identities \
	"{\"kind\":\"x509_certificate\",\"name\":\"dr-rehearsal-post-restore.example\",\"owner_id\":\"$OWNER\",\"issuer_id\":\"$ISSUER\"}" | jq -r .id)"
[ -n "$IDENT2" ] && [ "$IDENT2" != "null" ] || fail "restored instance cannot create a new identity"
post "$B_URL" "$TOKEN" rehearsal-issue2 "/api/v1/identities/$IDENT2/transitions" '{"to":"issued"}' >/dev/null \
	|| fail "restored instance cannot issue"
NEW_CERTS=0
for _ in $(seq 1 30); do
	NEW_CERTS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$B_URL/api/v1/certificates" | jq '[.items[]? | select((.subject // "") | contains("dr-rehearsal-post-restore.example"))] | length')"
	[ "${NEW_CERTS:-0}" -ge 1 ] && break
	sleep 1
done
[ "${NEW_CERTS:-0}" -ge 1 ] || fail "restored instance minted no NEW certificate within SLA"
say "instance B serves restored data and new issuance"
stop_server

# ------------------------------------------------- control: corrupted backup
say "control: a corrupted backup must fail the restore"
CORRUPT="$ROOT/backup-corrupt"
cp -r "$BACKUP" "$CORRUPT"
TARGET="$(find "$CORRUPT" -type f -size +64c | sort -rn -t/ -k1 | head -1)"
[ -n "$TARGET" ] || fail "no backup artifact to corrupt"
python3 - "$TARGET" <<'EOF'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:
    f.seek(32)
    chunk = bytearray(f.read(64))
    for i in range(len(chunk)):
        chunk[i] ^= 0xA5
    f.seek(32)
    f.write(chunk)
EOF
C_PORT="$(free_port)"; C_PG="$(free_port)"; C_NATS="$(free_port)"
start_infra "$C_PG" "$C_NATS"
C_CFG="$(write_config "$ROOT/c" "$C_PORT" "$C_PG" "$C_NATS")"
install -m 0600 "$ROOT/a/secrets-kek.bin" "$ROOT/c/secrets-kek.bin"
if run_bin "$C_CFG" --full-restore-dir "$CORRUPT" --backup-encryption-key-file "$KEYFILE" >"$ROOT/c.log" 2>&1; then
	tail -20 "$ROOT/c.log" >&2 || true
	fail "corrupted backup was ACCEPTED by --full-restore-dir"
fi
say "corrupted backup rejected (restore failed closed)"

say "OK — backup -> fresh-binary restore -> boot -> issue -> verify, and the corrupted control failed closed"
