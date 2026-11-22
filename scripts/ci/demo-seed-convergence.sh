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
        'outbox_count', (SELECT count(*) FROM outbox WHERE tenant_id = '${tenant_id}'),
        'outbox_active_retry_count', (SELECT count(*) FROM outbox o
             WHERE o.tenant_id = '${tenant_id}'
               AND NOT (o.destination LIKE 'notification.%' AND o.status = 'pending'
                        AND o.last_error = 'notification_receiver_not_configured')
               AND NOT (o.destination = 'connector.deploy' AND o.required_agent_role = 'host'
                        AND NOT EXISTS (SELECT 1 FROM agents a
                                        WHERE a.tenant_id = o.tenant_id
                                          AND a.status <> 'offboarded'))
               AND (o.status = 'processing' OR (o.status = 'pending'
                    AND COALESCE(o.last_error, '') <> 'delivery_deferred')))
      );"
}

jetstream_snapshot() {
  docker compose -f "$compose_file" exec -T nats \
    wget -qO- 'http://localhost:8222/jsz?streams=true' |
    jq -ec '[.account_details[]?.stream_detail[]?] |
      {total: ([.[].state.messages] | add // 0),
       streams: (map({key: (.config.name // .name // "unknown"), value: .state.messages}) | from_entries)}'
}

snapshot() {
  local postgres_json jetstream_json
  postgres_json="$(postgres_snapshot)"
  jetstream_json="$(jetstream_snapshot)"
  jq -cn --argjson postgres "$postgres_json" --argjson jetstream "$jetstream_json" \
    '{postgres:$postgres,jetstream_message_count:$jetstream.total,jetstream_streams:$jetstream.streams}'
}

stable_snapshot() {
  local previous="" current="" stable=0
  # Unconfigured notifications and host deployments without any live agent
  # cannot complete in the assembled demo. Their workers can still claim and
  # defer rows while the seed and event stream have settled. Other active work
  # must settle before the preserved-volume comparison.
  for _attempt in $(seq 1 360); do
    current="$(snapshot)"
    if [[ "$(jq -r '.postgres.outbox_active_retry_count' <<<"$current")" != "0" ]]; then
      previous=""
      stable=0
    elif [[ "$current" == "$previous" ]]; then
      stable=$((stable + 1))
      # Two matching 2-second reads can land between a worker's delayed
      # event append and its next retry. Require a continuous 30-second quiet
      # window before treating the event stream as settled.
      if [[ "$stable" -ge 15 ]]; then
        printf '%s\n' "$current"
        return 0
      fi
    else
      previous="$current"
      stable=0
    fi
    sleep 2
  done
  jq -c '{active_retry_count:.postgres.outbox_active_retry_count,
          outbox_count:.postgres.outbox_count,
          jetstream_message_count,
          jetstream_streams}' <<<"$current" >&2
  fail "assembled demo did not reach a stable inventory/event checkpoint"
}

seed_actor_events() {
  # A running demo has background workers. Their legitimate, actorless events
  # can advance all three JetStream streams during the repeat run. Query the
  # event-backed audit view inside the seed's own trust boundary and compare the
  # exact IDs attributed to its bootstrap subjects instead of global counts.
  docker compose -f "$compose_file" run --rm --no-deps --entrypoint node demo-seed -e '
    const { readFileSync } = require("node:fs");
    const subjects = new Set([
      "demo-seeder", "demo-key-custodian-one", "demo-key-custodian-two",
      "ci-release-bot", "incident-rotator",
    ]);
    (async () => {
      const token = readFileSync(process.env.TRSTCTL_DEMO_BOOTSTRAP_TOKEN_FILE, "utf8").trim();
      if (!token) throw new Error("demo bootstrap token is empty");
      const url = new URL("/api/v1/audit/events", process.env.TRSTCTL_SERVER);
      const response = await fetch(url, {headers: {authorization: `Bearer ${token}`}});
      if (!response.ok) throw new Error(`demo audit query failed: HTTP ${response.status}`);
      const body = await response.json();
      if (!Array.isArray(body.events) || !Array.isArray(body.readable_events || [])) {
        throw new Error("demo audit response has no event array");
      }
      const readable = new Map((body.readable_events || []).map(event => [event.id, event.actor?.subject]));
      const ids = body.events
        .filter(event => subjects.has(event.actor?.subject || readable.get(event.id)))
        .map(event => event.id).sort();
      if (ids.length === 0 || ids.some(id => typeof id !== "string" || !id)) {
        throw new Error("demo audit response has no valid seed-attributed event IDs");
      }
      console.log(JSON.stringify(ids));
    })().catch(error => { console.error(error.message); process.exitCode = 1; });
  '
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
first_seed_events="$(seed_actor_events)"

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
second_seed_events="$(seed_actor_events)"

if [[ "$(jq -c '.postgres' <<<"$first")" != "$(jq -c '.postgres' <<<"$second")" ||
      "$first_seed_events" != "$second_seed_events" ]] ||
   ! jq -en --argjson before "$first" --argjson after "$second" '
     ($before.jetstream_streams | keys) == ($after.jetstream_streams | keys) and
     ($after.jetstream_message_count >= $before.jetstream_message_count) and
     all($before.jetstream_streams | keys[];
         $after.jetstream_streams[.] >= $before.jetstream_streams[.])
   ' >/dev/null; then
  diff -u <(jq -S . <<<"$first") <(jq -S . <<<"$second") || true
  diff -u <(jq -S . <<<"$first_seed_events") <(jq -S . <<<"$second_seed_events") || true
  fail "seed snapshot changed across the preserved-volume rerun"
fi

echo "demo seed convergence passed: preserved inventory, owner uniqueness, outbox count, and seed-attributed event IDs are unchanged"
