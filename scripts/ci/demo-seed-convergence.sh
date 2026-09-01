#!/usr/bin/env bash
# AUD-66: prove the literal demo seed converges against preserved volumes.
set -euo pipefail

readonly compose_file="${TRSTCTL_DEMO_COMPOSE_FILE:-deploy/demo/docker-compose.yml}"
readonly tenant_id="11111111-1111-4111-8111-111111111111"

fail() {
  echo "demo seed convergence: $*" >&2
  exit 1
}

postgres_snapshot() {
  docker compose -f "$compose_file" exec -T postgres \
    psql -X -A -t -U trstctl -d trstctl -v ON_ERROR_STOP=1 -c "
      SELECT jsonb_build_object(
        'owners', (SELECT jsonb_agg(jsonb_build_array(id, kind, name, email) ORDER BY name, email, id)
                     FROM owners WHERE tenant_id = '${tenant_id}'),
        'owner_count', (SELECT count(*) FROM owners WHERE tenant_id = '${tenant_id}'),
        'owner_logical_count', (SELECT count(DISTINCT (name, email)) FROM owners WHERE tenant_id = '${tenant_id}'),
        'identities', (SELECT jsonb_agg(jsonb_build_array(id, name, status, owner_id, issuer_id) ORDER BY name, id)
                         FROM identities WHERE tenant_id = '${tenant_id}'),
        'certificates', (SELECT count(*) FROM certificates WHERE tenant_id = '${tenant_id}'),
        'members', (SELECT jsonb_agg(jsonb_build_array(subject, source, status) ORDER BY subject)
                      FROM tenant_members WHERE tenant_id = '${tenant_id}'),
        'secrets', (SELECT jsonb_agg(jsonb_build_array(name, version) ORDER BY name)
                      FROM secret_store WHERE tenant_id = '${tenant_id}'),
        'api_token_count', (SELECT count(*) FROM api_tokens WHERE tenant_id = '${tenant_id}'),
        'outbox_count', (SELECT count(*) FROM outbox WHERE tenant_id = '${tenant_id}')
      );"
}

jetstream_message_count() {
  docker compose -f "$compose_file" exec -T nats \
    wget -qO- 'http://localhost:8222/jsz?streams=true' |
    jq -er '[.account_details[]?.stream_detail[]?.state.messages] | add // 0'
}

snapshot() {
  local postgres_json jetstream_messages
  postgres_json="$(postgres_snapshot)"
  jetstream_messages="$(jetstream_message_count)"
  jq -cn --argjson postgres "$postgres_json" --argjson events "$jetstream_messages" \
    '{postgres:$postgres,jetstream_message_count:$events}'
}

stable_snapshot() {
  local previous="" current="" stable=0
  for _attempt in $(seq 1 60); do
    current="$(snapshot)"
    if [[ "$current" == "$previous" ]]; then
      stable=$((stable + 1))
      if [[ "$stable" -ge 2 ]]; then
        printf '%s\n' "$current"
        return 0
      fi
    else
      previous="$current"
      stable=0
    fi
    sleep 2
  done
  fail "assembled demo did not reach a stable inventory/event checkpoint"
}

wait_for_seed() {
  local container_id state exit_code
  container_id="$(docker compose -f "$compose_file" ps -aq demo-seed)"
  [[ -n "$container_id" ]] || fail "demo-seed container does not exist"
  state="$(docker inspect --format '{{.State.Status}}' "$container_id")"
  if [[ "$state" == "running" ]]; then
    if ! docker compose -f "$compose_file" wait demo-seed; then
      docker compose -f "$compose_file" logs --no-color demo-seed >&2 || true
      fail "demo-seed exited unsuccessfully"
    fi
  fi
  exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$container_id")"
  if [[ "$exit_code" != "0" ]]; then
    docker compose -f "$compose_file" logs --no-color demo-seed >&2 || true
    fail "demo-seed exited with status $exit_code"
  fi
}

wait_for_seed
first="$(stable_snapshot)"

first_owner_count="$(jq -r '.postgres.owner_count' <<<"$first")"
first_logical_count="$(jq -r '.postgres.owner_logical_count' <<<"$first")"
[[ "$first_owner_count" == "$first_logical_count" ]] ||
  fail "owners contain duplicates before the repeat run: $first_owner_count rows, $first_logical_count logical owners"

# The assembled dependencies are already running and are part of the preserved
# state under test. Asking Compose to reconcile them here can recreate the
# control plane on some Compose releases, which legitimately emits restart
# events and contaminates this seed-only idempotency oracle.
docker compose -f "$compose_file" run --rm --no-deps demo-seed
second="$(stable_snapshot)"

if [[ "$first" != "$second" ]]; then
  diff -u <(jq -S . <<<"$first") <(jq -S . <<<"$second") || true
  fail "seed snapshot changed across the preserved-volume rerun"
fi

echo "demo seed convergence passed: preserved inventory, owner uniqueness, outbox count, and JetStream message count are unchanged"
