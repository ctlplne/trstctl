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
  local previous="" current="" last_streams="" stable=0
  # Unconfigured notifications and host deployments without any live agent
  # cannot complete in the assembled demo. A notification retry preserves its
  # pending outbox intent while an operator can configure a receiver; the
  # finite attempt budget still applies. Those workers can claim rows while
  # the seed has settled. Other active work must settle before
  # the preserved-volume comparison. CI has observed all three JetStream
  # streams advancing during this window; the producer is being traced below.
  # Require nondecreasing counts and compare seed-attributed IDs after replay.
  for _attempt in $(seq 1 360); do
    current="$(snapshot)"
    if [[ -n "$last_streams" ]] &&
       ! jq -en --argjson before "$last_streams" --argjson after "$current" '
         ($before.jetstream_streams | keys) == ($after.jetstream_streams | keys) and
         ($after.jetstream_message_count >= $before.jetstream_message_count) and
         all($before.jetstream_streams | keys[];
             $after.jetstream_streams[.] >= $before.jetstream_streams[.])
       ' >/dev/null; then
      fail "event stream regressed while waiting for the demo seed checkpoint"
    fi
    last_streams="$current"
    if [[ "$(jq -r '.postgres.outbox_active_retry_count' <<<"$current")" != "0" ]]; then
      previous=""
      stable=0
    elif [[ -n "$previous" &&
            "$(jq -cS '.postgres' <<<"$current")" == "$(jq -cS '.postgres' <<<"$previous")" ]]; then
      stable=$((stable + 1))
      # Two matching 2-second reads can land between a worker's delayed
      # projection and its next retry. Require a continuous 30-second stable
      # tenant inventory/outbox window before the preserved-volume comparison.
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
  # A checkpoint can fail before the post-pass trace below. Preserve the
  # original failure while reporting the types that appeared during its wait.
  if [[ "${TRSTCTL_DEMO_EVENT_TRACE_SECONDS:-0}" == "300" && -n "${trace_baseline_audit:-}" ]]; then
    if failed_audit="$(seed_actor_events)"; then
      report_new_audit_types "$trace_baseline_audit" "$failed_audit" "during failed checkpoint" >&2 || true
    fi
  fi
  fail "assembled demo did not reach a stable tenant inventory/outbox checkpoint"
}

seed_actor_events() {
  # Query the event-backed audit view inside the seed's trust boundary. Keep
  # event IDs in memory for comparison, but emit only event types in CI traces.
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
      const records = body.events.map(event => ({id: event.id, type: event.type}));
      if (records.some(event => typeof event.id !== "string" || !event.id ||
                                typeof event.type !== "string" || !event.type)) {
        throw new Error("demo audit response has an invalid event ID or type");
      }
      console.log(JSON.stringify({seed_ids: ids, records}));
    })().catch(error => { console.error(error.message); process.exitCode = 1; });
  '
}

report_new_audit_types() {
  jq -rnc --argjson before "$1" --argjson after "$2" --arg label "$3" '
    ($before.records | map(.id)) as $known |
    [$after.records[] | select(.id as $id | ($known | index($id)) == null) | .type] |
    group_by(.) | map({type: .[0], count: length}) |
    "demo background event types \($label): \(.)"
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
trace_baseline_audit=""
if [[ "${TRSTCTL_DEMO_EVENT_TRACE_SECONDS:-0}" == "300" ]]; then
  trace_baseline_audit="$(seed_actor_events)"
fi
first="$(stable_snapshot)"
first_audit="$(seed_actor_events)"
first_seed_events="$(jq -cS '.seed_ids' <<<"$first_audit")"

first_owner_count="$(jq -r '.postgres.owner_count' <<<"$first")"
first_logical_count="$(jq -r '.postgres.owner_logical_count' <<<"$first")"
[[ "$first_owner_count" == "$first_logical_count" ]] ||
  fail "owners contain duplicates before the repeat run: $first_owner_count rows, $first_logical_count logical owners"

# The assembled dependencies are already running and are part of the preserved
# state under test. Asking Compose to reconcile them here can recreate the
# control plane on some Compose releases, which legitimately emits restart
# events and contaminates this seed-only idempotency oracle.
# Measure outbox rows across the replay itself. Background work may enqueue a
# new row during the later settling window even when the seed makes no calls.
before_replay="$(postgres_snapshot)"
docker compose -f "$compose_file" run --rm --no-deps demo-seed
after_replay="$(postgres_snapshot)"
second="$(stable_snapshot)"
second_audit="$(seed_actor_events)"
second_seed_events="$(jq -cS '.seed_ids' <<<"$second_audit")"

if [[ "$(jq -c '.outbox_count' <<<"$before_replay")" != "$(jq -c '.outbox_count' <<<"$after_replay")" ||
      "$(jq -c '.postgres | del(.outbox_count)' <<<"$first")" != "$(jq -c '.postgres | del(.outbox_count)' <<<"$second")" ||
      "$first_seed_events" != "$second_seed_events" ]] ||
   ! jq -en --argjson before "$first" --argjson after "$second" '
     ($before.jetstream_streams | keys) == ($after.jetstream_streams | keys) and
     ($after.jetstream_message_count >= $before.jetstream_message_count) and
     all($before.jetstream_streams | keys[];
         $after.jetstream_streams[.] >= $before.jetstream_streams[.])
   ' >/dev/null; then
  diff -u <(jq -S . <<<"$first") <(jq -S . <<<"$second") || true
  diff -u <(jq -S . <<<"$before_replay") <(jq -S . <<<"$after_replay") || true
  diff -u <(jq -S . <<<"$first_seed_events") <(jq -S . <<<"$second_seed_events") || true
  fail "seed snapshot changed across the preserved-volume rerun"
fi

echo "demo seed convergence passed: preserved inventory, owner uniqueness, outbox count across replay, and seed-attributed event IDs are unchanged"

# Diagnostic window for identifying the producer of stream growth. A missing
# notification receiver only changes its outbox row; it does not append an
# event. This trace runs after the gate and prints new event types, never
# payloads or IDs. Once the producer is known, remove the temporary CI opt-in.
if [[ "${TRSTCTL_DEMO_EVENT_TRACE_SECONDS:-0}" == "300" ]]; then
  sleep 300
  trace_audit="$(seed_actor_events)"
  report_new_audit_types "$first_audit" "$trace_audit" "over replay plus 300s"
fi
