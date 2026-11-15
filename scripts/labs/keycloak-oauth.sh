#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# A239 and A239-L7 lab: OAuth 2.0 leases against stock Keycloak 26.8.1, the
# pinned digest below, which must already be cached (it is never pulled), in
# a throwaway container on a loopback port. Realm "lab" has the client scopes
# orders.read and orders.write and two confidential clients: "trstctl-leases"
# (client secret, client credentials) and "trstctl-leases-jwt" (Keycloak's
# client-jwt: a JWT signed with an RSA key this script generates, whose
# certificate Keycloak holds; client credentials, and the password grant only
# so the test can obtain a refresh token once). Both service accounts and the
# user "orders-bot" may read the realm through the admin API, which is the
# protected resource curl calls. Passwords are random; the key, the client
# secret and the passwords stay in a private temp directory while the proofs
# run and are never printed.
set -euo pipefail
IMAGE=quay.io/keycloak/keycloak@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b
docker image inspect "$IMAGE" > /dev/null
repo=$(cd "$(dirname "$0")/../.." && pwd)
# Evidence goes under TRSTCTL_LAB_EVIDENCE when set; the tests keep the
# default TMPDIR (the signer's unix socket needs a short path).
proof=$(mktemp -d "${TRSTCTL_LAB_EVIDENCE:-${TMPDIR:-/tmp}}/trstctl-keycloak-oauth.XXXXXX")
chmod 700 "$proof"
lab=''
trap 'if [ -n "$lab" ]; then docker rm -f "$lab" > /dev/null 2>&1 || true; fi; rm -f "$proof"/client-key.pem "$proof"/client-secret "$proof"/*-password; printf "Evidence: %s\n" "$proof"' EXIT
(
  umask 077
  python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_urlsafe(18))' > "$proof/admin-password"
  python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_urlsafe(18))' > "$proof/user-password"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$proof/client-key.pem" 2> /dev/null
  openssl req -x509 -key "$proof/client-key.pem" -out "$proof/client-cert.pem" -days 1 -subj /CN=trstctl-leases-jwt 2> /dev/null
)
lab=$(docker run -d --rm --pull never --label trstctl.lab=keycloak-oauth -p 127.0.0.1::8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$proof/admin-password")" "$IMAGE" start-dev)
port=$(docker port "$lab" 8080/tcp | head -1 | sed 's/.*://')
base="http://127.0.0.1:$port"
echo "Keycloak $(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}') on $base"
for _ in $(seq 1 120); do curl -fsS -o /dev/null "$base/realms/master" 2> /dev/null && break; sleep 1; done
curl -fsS -o /dev/null "$base/realms/master"
admin_token=$(curl -fsS -d grant_type=password -d client_id=admin-cli -d username=lab-admin --data-urlencode "password@$proof/admin-password" \
  "$base/realms/master/protocol/openid-connect/token" | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')
api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "$method" -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' "$base/admin/realms$path" "$@"
}
json_id() { python3 -c "import json, sys; print(next(x['id'] for x in json.load(sys.stdin) if x[sys.argv[1]] == sys.argv[2]))" "$@"; }
api POST "" -d '{"realm":"lab","enabled":true}'
for scope in orders.read orders.write; do
  api POST /lab/client-scopes -d "{\"name\":\"$scope\",\"protocol\":\"openid-connect\",\"attributes\":{\"include.in.token.scope\":\"true\"}}"
done
cert=$(openssl x509 -in "$proof/client-cert.pem" -outform der | base64 | tr -d '\n')
api POST /lab/clients -d '{"clientId":"trstctl-leases","enabled":true,"publicClient":false,"serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false}'
api POST /lab/clients -d "{\"clientId\":\"trstctl-leases-jwt\",\"enabled\":true,\"publicClient\":false,\"clientAuthenticatorType\":\"client-jwt\",\"serviceAccountsEnabled\":true,\"standardFlowEnabled\":false,\"directAccessGrantsEnabled\":true,\"attributes\":{\"jwt.credential.certificate\":\"$cert\",\"use.jwks.url\":\"false\",\"token.endpoint.auth.signing.alg\":\"RS256\"}}"
rm_id=$(api GET '/lab/clients?clientId=realm-management' | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])')
view_realm=$(api GET "/lab/clients/$rm_id/roles/view-realm")
for client in trstctl-leases trstctl-leases-jwt; do
  cid=$(api GET "/lab/clients?clientId=$client" | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])')
  for name in profile email; do
    sid=$(api GET "/lab/clients/$cid/default-client-scopes" | python3 -c "import json, sys; print(next((s['id'] for s in json.load(sys.stdin) if s['name'] == '$name'), ''))")
    if [ -n "$sid" ]; then api DELETE "/lab/clients/$cid/default-client-scopes/$sid"; fi
  done
  for name in orders.read orders.write; do
    sid=$(api GET /lab/client-scopes | json_id name "$name")
    api PUT "/lab/clients/$cid/optional-client-scopes/$sid"
  done
  sa=$(api GET "/lab/clients/$cid/service-account-user" | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')
  api POST "/lab/users/$sa/role-mappings/clients/$rm_id" -d "[$view_realm]"
  if [ "$client" = trstctl-leases ]; then
    (umask 077; api GET "/lab/clients/$cid/client-secret" | python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["value"])' > "$proof/client-secret")
  fi
done
python3 -c 'import json, sys; print(json.dumps({"username": "orders-bot", "enabled": True, "emailVerified": True, "firstName": "Orders",
  "lastName": "Bot", "email": "orders-bot@lab.invalid", "credentials": [{"type": "password", "value": open(sys.argv[1]).read(), "temporary": False}]}))' \
  "$proof/user-password" | api POST /lab/users -d @-
user=$(api GET '/lab/users?username=orders-bot&exact=true' | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])')
api POST "/lab/users/$user/role-mappings/clients/$rm_id" -d "[$view_realm]"
echo "realm lab configured: trstctl-leases (secret), trstctl-leases-jwt (client-jwt), orders-bot; optional scopes orders.read/orders.write; view-realm"
cd "$repo"
TRSTCTL_A239_KEYCLOAK_URL="$base" TRSTCTL_A239_KEYCLOAK_SECRET_FILE="$proof/client-secret" \
  TRSTCTL_A239L7_KEYCLOAK_URL="$base" TRSTCTL_A239L7_KEYCLOAK_KEY_FILE="$proof/client-key.pem" TRSTCTL_A239L7_KEYCLOAK_USER_PASSWORD_FILE="$proof/user-password" \
  go test -count=1 -v -run '^(TestServedDynamicOAuthLeaseRevokedByKeycloakA239|TestServedDynamicOAuthJWTClientAndRefreshRoleByKeycloakA239L7)$' ./internal/server/ | tee "$proof/test.log"
grep -q '^--- PASS: TestServedDynamicOAuthLeaseRevokedByKeycloakA239 ' "$proof/test.log"
grep -q '^--- PASS: TestServedDynamicOAuthJWTClientAndRefreshRoleByKeycloakA239L7 ' "$proof/test.log"
