#!/usr/bin/env bash
#
# scripts/ci/compose-e2e.sh — EXC-GATE-01 end-to-end gate against the running stack.
#
# The caller (the CI job) brings up the compose eval stack and exports BASE_URL
# (e.g. https://localhost:8443). This proves the SHIPPED deployment works end to end
# against real external PostgreSQL + NATS + the separate isolated signer process:
#   1. the control-plane container boots and serves (/readyz),
#   2. served auth + RLS hold (unauthenticated 401; a bootstrapped token 200),
#   3. a real event-sourced mutation round-trips (create owner -> read it back),
#   4. the served issuance lifecycle runs: issue a cert, RETRY the issuing transition
#      with the same Idempotency-Key and assert NO second credential (AN-5), revoke,
#   5. the served PKI surfaces are mounted and reflect revocation: ACME /directory
#      advertises newOrder + revokeCert, EST /cacerts hands back the issuing CA
#      chain, OCSP reports the revoked serial as revoked, and the CRL lists it.
#
# The bootstrap API token is minted INSIDE the running control-plane container
# (`docker compose exec ... trstctl token create`): the compose Postgres has no host
# port and the token must land in the same database the server reads, so the
# network-trust-free first-run bootstrap (WIRE-002) runs where the DSN resolves. This
# is exactly the operator's real first-run step.
#
# Requires: docker compose (the eval stack up), a reachable served control plane
# (BASE_URL), curl, jq, openssl.
set -euo pipefail

say()  { printf '\n>> %s\n' "$*"; }
fail() { printf '::error::compose-e2e: %s\n' "$*"; exit 1; }

compose_e2e_normalize_uuid() {
  local uuid="$1"
  uuid="$(printf '%s' "$uuid" | tr '[:upper:]' '[:lower:]')"
  if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    printf '%s\n' "$uuid"
    return 0
  fi
  return 1
}

compose_e2e_uuid() {
  local uuid tmp
  if command -v uuidgen >/dev/null 2>&1; then
    uuid="$(uuidgen 2>/dev/null || true)"
    compose_e2e_normalize_uuid "$uuid" && return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    uuid="$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)"
    compose_e2e_normalize_uuid "$uuid" && return 0
  fi
  if command -v python >/dev/null 2>&1; then
    uuid="$(python -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)"
    compose_e2e_normalize_uuid "$uuid" && return 0
  fi
  if command -v go >/dev/null 2>&1; then
    tmp="$(mktemp "${TMPDIR:-/tmp}/compose-e2e-uuid.XXXXXX.go")" || return 1
    cat >"$tmp" <<'EOF'
package main

import (
	"crypto/rand"
	"fmt"
	"io"
)

func main() {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	fmt.Printf("%x-%x-%x-%x-%x\n", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
EOF
    uuid="$(go run "$tmp" 2>/dev/null || true)"
    rm -f "$tmp"
    compose_e2e_normalize_uuid "$uuid" && return 0
  fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    compose_e2e_normalize_uuid "$uuid" && return 0
  fi
  return 1
}

compose_e2e_init_ids() {
  if [[ -z "${TENANT:-}" ]]; then
    if [[ "${COMPOSE_E2E_UUID_SELFTEST:-0}" == "1" ]]; then
      TENANT="$(compose_e2e_uuid)" || return 1
    else
      TENANT="${COMPOSE_E2E_TENANT:-11111111-1111-4111-8111-111111111111}"
    fi
  else
    TENANT="$(compose_e2e_normalize_uuid "$TENANT")" || return 1
  fi
  compose_e2e_normalize_uuid "$TENANT" >/dev/null || return 1
  if [[ -z "${IDEM_BASE:-}" ]]; then
    local idem_uuid
    idem_uuid="$(compose_e2e_uuid)" || return 1
    IDEM_BASE="e2e-${idem_uuid}"
  fi
}

if [[ "${COMPOSE_E2E_UUID_SELFTEST:-0}" == "1" ]]; then
  compose_e2e_init_ids || exit 1
  printf 'TENANT=%s\n' "$TENANT"
  printf 'IDEM_BASE=%s\n' "$IDEM_BASE"
  exit 0
fi

BASE_URL="${BASE_URL:?set BASE_URL to the served control plane, e.g. https://localhost:8443}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.yml}"
COMPOSE_E2E_TENANT="${COMPOSE_E2E_TENANT:-11111111-1111-4111-8111-111111111111}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
compose_e2e_init_ids || fail "could not generate portable UUIDs for TENANT/IDEM_BASE"
CURL=(curl -fsS -k)          # -k: the eval stack serves a self-signed cert (TLS internal mode)
Q=(curl -s -k -o /dev/null -w '%{http_code}')
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Every mutating POST must carry an Idempotency-Key — the served API rejects a mutation
# without one (AN-5). post <idempotency-key> <path> <json-body>. AUTH is resolved at
# call time (set after the bootstrap-token step).
post() {
  local key="$1" path="$2" body="$3" out code
  out="$(mktemp)"
  code=$(curl -sS -k "${AUTH[@]}" -H "Idempotency-Key: $key" -H "Content-Type: application/json" \
    -XPOST "$BASE_URL$path" -d "$body" -w '%{http_code}' -o "$out" || true)
  case "$code" in
    2*) cat "$out"; rm -f "$out";;
    *)
      printf '::error::compose-e2e: POST %s returned HTTP %s\n' "$path" "$code" >&2
      sed 's/^/response: /' "$out" >&2
      rm -f "$out"
      return 1
      ;;
  esac
}

say "1. control plane is serving (/readyz)"
code=$("${Q[@]}" "$BASE_URL/readyz" || true)
[ "$code" = "200" ] || fail "/readyz returned '$code' (control plane not serving on $BASE_URL)"

say "2. served auth + RLS: unauthenticated is rejected, a bootstrapped token is accepted"
code=$("${Q[@]}" "$BASE_URL/api/v1/owners" || true)
[ "$code" = "401" ] || fail "unauthenticated GET /api/v1/owners returned '$code', want 401 (auth not enforced)"
# A first-run, network-trust-free token, minted INSIDE the control-plane container so it
# lands in the same Postgres the server reads (the compose DB has no host port). Grant
# certs:issue for this throwaway EVAL run so the gate can drive served issuance
# (production withholds it — the loaded-gun guard, RED-004).
TOKEN=$("${COMPOSE[@]}" exec -T trstctl /usr/local/bin/trstctl token create \
          --tenant "$TENANT" --tenant-name e2e \
          --scopes "owners:read,owners:write,issuers:read,issuers:write,identities:read,identities:write,certs:read,certs:write,certs:issue" \
        2>/dev/null | grep -oE 'trst_[A-Za-z0-9_.-]+' | head -1)
[ -n "${TOKEN:-}" ] || fail "bootstrap token mint (docker compose exec trstctl token create) produced no trst_ token"
AUTH=(-H "Authorization: Bearer ${TOKEN}")
code=$("${Q[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/owners" || true)
[ "$code" = "200" ] || fail "bootstrapped GET /api/v1/owners returned '$code', want 200"

say "   activate the tenant-bound eval protocol profile through the same first-run API the wizard uses"
PROTOCOL_PROFILE=$(post "${IDEM_BASE}-protocol-profile" /api/v1/setup/protocols/activate '{}')
jq -e --argjson want 7 '.profile == "eval" and .active == true and (.protocols | length) == $want' <<<"$PROTOCOL_PROFILE" >/dev/null \
  || fail "eval protocol activation did not report all seven shipped protocol surfaces: $PROTOCOL_PROFILE"

say "3. event-sourced mutation round-trips (create owner -> read back)"
OWNER=$(post "${IDEM_BASE}-owner" /api/v1/owners '{"kind":"workload","name":"e2e"}' | jq -r .id)
[ -n "$OWNER" ] && [ "$OWNER" != "null" ] || fail "owner create returned no id"
"${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/owners/$OWNER" >/dev/null || fail "could not read back the created owner $OWNER"

say "4. served issuance lifecycle: issue -> idempotent retry -> revoke"
# Request bodies match the API schema (ground truth: internal/projections/
# issuance_e2e_test.go): owner kind=workload, issuer kind=x509_ca WITH a chain, and an
# identity kind=x509_certificate whose name becomes the issued leaf's subject/CN.
ISSUER=$(post "${IDEM_BASE}-issuer" /api/v1/issuers \
          '{"kind":"x509_ca","name":"e2e-ca","chain":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"]}' | jq -r .id)
[ -n "$ISSUER" ] && [ "$ISSUER" != "null" ] || fail "issuer create returned no id"
IDENT_NAME="${IDEM_BASE}.example"
IDENT=$(post "${IDEM_BASE}-identity" /api/v1/identities \
          "{\"kind\":\"x509_certificate\",\"name\":\"$IDENT_NAME\",\"owner_id\":\"$OWNER\",\"issuer_id\":\"$ISSUER\"}" | jq -r .id)
[ -n "$IDENT" ] && [ "$IDENT" != "null" ] || fail "identity create returned no id"
# Stable key across the two issue() calls so the retry is the SAME operation (AN-5).
IDEM="${IDEM_BASE}-issue"
issue() { post "$IDEM" "/api/v1/identities/$IDENT/transitions" '{"to":"issued"}'; }
certificate_field() {
  local field="$1"
  "${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates" \
    | jq -r --arg subject "$IDENT_NAME" --arg field "$field" \
      '[.items[]? | select((.subject // "") | contains($subject)) | .[$field] // empty][0] // ""'
}
certs() { "${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates" | jq --arg subject "$IDENT_NAME" '[.items[]? | select((.subject // "") | contains($subject))] | length'; }
issue >/dev/null || fail "transition->issued failed"
# Issuance is ASYNC in the deployed stack: the transition enqueues an outbox entry that a
# background worker mints from (the in-binary tests Drain synchronously instead). Poll
# for the minted cert to appear in inventory.
n1=0
for _ in $(seq 1 30); do n1=$(certs); [ "${n1:-0}" -ge 1 ] && break; sleep 1; done
[ "${n1:-0}" -ge 1 ] || fail "no certificate minted for the identity within SLA (got '$n1')"
# A retried transition with the SAME Idempotency-Key must NOT mint a second one (AN-5).
issue >/dev/null || fail "idempotent retry of transition->issued failed"
sleep 3   # allow any (erroneous) second mint to surface before re-counting
n2=$(certs)
[ "$n1" = "$n2" ] || fail "AN-5 VIOLATED: retry with same Idempotency-Key minted another credential ($n1 -> $n2)"
say "   idempotent issuance holds: $n1 == $n2 cert(s)"
SERIAL="$(certificate_field serial)"
[ -n "$SERIAL" ] || fail "issued certificate for $IDENT_NAME has no serial; OCSP/CRL revocation cannot be asserted"
post "${IDEM_BASE}-revoke" "/api/v1/identities/$IDENT/transitions" '{"to":"revoked"}' >/dev/null || fail "transition->revoked failed"
revoked_status=""
for _ in $(seq 1 30); do
  revoked_status="$(certificate_field status || true)"
  [ "$revoked_status" = "revoked" ] && break
  sleep 1
done
[ "$revoked_status" = "revoked" ] || fail "certificate serial $SERIAL did not project to revoked status within SLA (last status '$revoked_status')"

say "5. served PKI surfaces are mounted and reflect revocation: ACME directory + OCSP responder + CRL + EST cacerts"
"${CURL[@]}" "$BASE_URL/directory" | jq -e '.newOrder and .revokeCert' >/dev/null || fail "served ACME /directory missing newOrder/revokeCert"
# Pull the issuing CA chain the deployment serves (RFC 7030 §4.1 cacerts, unauthenticated)
# and write it as PEM for the zlint conformance step. base64 PKCS#7 -> DER -> PEM certs.
if "${CURL[@]}" "$BASE_URL/.well-known/est/cacerts" 2>/dev/null | base64 -d 2>/dev/null \
     | openssl pkcs7 -inform DER -print_certs -out served-ca.pem 2>/dev/null \
   && [ -s served-ca.pem ]; then
  say "   served EST /cacerts returned the issuing CA chain -> served-ca.pem ($(grep -c 'BEGIN CERTIFICATE' served-ca.pem) cert(s))"
else
  fail "served EST /cacerts did not return a parseable CA chain (PKI surface not mounted?)"
fi

ocsp_req="$tmpdir/revoked.ocsp.req"
ocsp_resp="$tmpdir/revoked.ocsp.der"
openssl ocsp -issuer served-ca.pem -serial "0x$SERIAL" -reqout "$ocsp_req" -no_nonce >/dev/null 2>&1 \
  || fail "could not build OCSP request for revoked serial $SERIAL"
"${CURL[@]}" -H 'Content-Type: application/ocsp-request' --data-binary "@$ocsp_req" \
  "$BASE_URL/ocsp/$TENANT" -o "$ocsp_resp" \
  || fail "served OCSP responder did not return a response for revoked serial $SERIAL"
ocsp_text="$(openssl ocsp -respin "$ocsp_resp" -issuer served-ca.pem -serial "0x$SERIAL" -CAfile served-ca.pem -resp_text -no_nonce 2>&1)" \
  || fail "served OCSP response for revoked serial $SERIAL did not verify:\n$ocsp_text"
printf '%s\n' "$ocsp_text" | grep -qi 'cert status: revoked' \
  || fail "served OCSP response for serial $SERIAL did not report revoked:\n$ocsp_text"
say "   served OCSP reports serial $SERIAL revoked"

crl_der="$tmpdir/served.crl.der"
for _ in $(seq 1 30); do
  if "${CURL[@]}" "$BASE_URL/crl/$TENANT" -o "$crl_der" 2>/dev/null && [ -s "$crl_der" ]; then
    break
  fi
  sleep 1
done
[ -s "$crl_der" ] || fail "served CRL for tenant $TENANT was not published within SLA"
crl_verify="$(openssl crl -inform DER -in "$crl_der" -CAfile served-ca.pem -verify -noout 2>&1)" \
  || fail "served CRL signature did not verify against the issuing CA:\n$crl_verify"
crl_text="$(openssl crl -inform DER -in "$crl_der" -noout -text 2>&1)" \
  || fail "served CRL could not be parsed:\n$crl_text"
if ! awk -F': ' '/Serial Number:/ {v=$2; gsub(/[^0-9A-Fa-f]/, "", v); print tolower(v)}' <<<"$crl_text" | grep -Eiq "^0*${SERIAL}$"; then
  fail "served CRL does not list revoked serial $SERIAL"
fi
say "   CRL lists revoked serial $SERIAL"

say "EXC-GATE-01 e2e PASS: deploy -> served auth -> mutation -> issue/idempotent/revoke -> OCSP+CRL reflect revocation -> ACME+cacerts mounted"
