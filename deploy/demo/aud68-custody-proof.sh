#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1

# AUD-68 assembled proof: every Docker object is scoped to one freshly generated
# Compose project. The script never addresses the ordinary `trstctl-demo` project.
set -Eeuo pipefail
umask 077

readonly tenant_id="11111111-1111-4111-8111-111111111111"
readonly tenant_name="Acme Robotics Demo"
readonly read_scopes="certs:read,audit:read,access:read,graph:read"
readonly api_url="https://127.0.0.1:9443/api/v1/certificates?limit=1"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"
compose_file="${script_dir}/docker-compose.yml"

# mktemp owns the uniqueness decision. The exclusive directory is also where all
# mode-0600 token, response, and expected-failure files live.
proof_tmp="$(mktemp -d "${TMPDIR:-/tmp}/trstctl-demo-custody-proof.XXXXXXXX")"
proof_suffix="${proof_tmp##*.}"
proof_suffix="$(printf '%s' "${proof_suffix}" | tr '[:upper:]_' '[:lower:]-')"
proof_project="trstctl-demo-custody-proof-${proof_suffix}"
if [[ ! "${proof_project}" =~ ^trstctl-demo-custody-proof-[a-z0-9][a-z0-9-]{7,}$ ]]; then
  printf 'AUD-68 proof: refusing invalid generated project name %q\n' "${proof_project}" >&2
  rmdir -- "${proof_tmp}"
  exit 2
fi

# Compose's ordinary image names are intentionally stable for normal demo use.
# This proof overrides them with names derived from the same exclusive suffix as
# the project, so --build cannot retag an image used by a preserved demo stack.
readonly proof_control_image="ctlplne-demo-control:aud68-${proof_suffix}"
readonly proof_seed_image="ctlplne-demo-seed:aud68-${proof_suffix}"
export TRSTCTL_DEMO_CONTROL_IMAGE="${proof_control_image}"
export TRSTCTL_DEMO_SEED_IMAGE="${proof_seed_image}"

# Compose v2's deterministic resource names are part of the collision preflight.
# Do not let an ambient compatibility switch change container separators.
unset COMPOSE_COMPATIBILITY
compose=(docker compose -p "${proof_project}" -f "${compose_file}")
readonly -a proof_services=(
  postgres nats localstack oidc-keys managedkeys-config signer trstctl demo-oidc
  oidc-loopback localstack-loopback localstack-signer-loopback demo-seed
)
readonly -a proof_volumes=(
  pgdata natsdata localstack signersock signerkeys seedstate secrets trstctldata publictrust demoidp managedkeys
)
proof_started=0
proof_namespace_owned=0
wrong_kek_volume="${proof_project}-wrong-kek"
wrong_kek_volume_created=0
declare -a artifacts=()

cleanup() {
  local rc=$?
  local artifact
  local proof_image
  trap - EXIT INT TERM
  set +e
  if (( proof_started )); then
    if ! "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
      printf 'AUD-68 proof: cleanup failed for exact project %s\n' "${proof_project}" >&2
      if (( rc == 0 )); then
        rc=1
      fi
    fi
  fi
  if (( wrong_kek_volume_created )) && docker volume inspect "${wrong_kek_volume}" >/dev/null 2>&1; then
    if ! docker volume rm "${wrong_kek_volume}" >/dev/null; then
      printf 'AUD-68 proof: cleanup failed for exact volume %s\n' "${wrong_kek_volume}" >&2
      if (( rc == 0 )); then
        rc=1
      fi
    fi
  fi
  if (( proof_namespace_owned )); then
    for proof_image in "${proof_seed_image}" "${proof_control_image}"; do
      if docker image inspect "${proof_image}" >/dev/null 2>&1; then
        if ! docker image rm "${proof_image}" >/dev/null; then
          printf 'AUD-68 proof: cleanup failed for exact image %s\n' "${proof_image}" >&2
          if (( rc == 0 )); then
            rc=1
          fi
        fi
      fi
    done
  fi
  for artifact in "${artifacts[@]}"; do
    if [[ "${artifact}" == "${proof_tmp}/"* ]]; then
      rm -f -- "${artifact}"
    fi
  done
  if ! rmdir -- "${proof_tmp}" 2>/dev/null; then
    printf 'AUD-68 proof: private temporary directory was not empty: %s\n' "${proof_tmp}" >&2
    if (( rc == 0 )); then
      rc=1
    fi
  fi
  exit "${rc}"
}

assert_named_object_absent() {
  local kind=$1
  local name=$2
  local existing
  case "${kind}" in
    container) existing="$(docker ps -aq --filter "name=^/${name}$")" ;;
    volume) existing="$(docker volume ls -q --filter "name=^${name}$")" ;;
    network) existing="$(docker network ls -q --filter "name=^${name}$")" ;;
    image) existing="$(docker image ls -q --filter "reference=${name}")" ;;
    *) die "internal proof error: unsupported Docker object kind ${kind}" ;;
  esac
  [[ -z "${existing}" ]] || die "generated ${kind} name already exists; refusing exact collision: ${name}"
}

assert_project_is_fresh() {
  local existing
  local service_name
  local volume_name

  # Labels find every Compose-owned leftover, including scaled and one-off
  # containers. Exact names separately reject unlabeled objects Compose might
  # otherwise adopt (named volumes are the dangerous case for `down --volumes`).
  existing="$({
    docker ps -aq --filter "label=com.docker.compose.project=${proof_project}"
    docker network ls -q --filter "label=com.docker.compose.project=${proof_project}"
    docker volume ls -q --filter "label=com.docker.compose.project=${proof_project}"
  } | tr -d '[:space:]')"
  [[ -z "${existing}" ]] ||
    die "generated project name already owns Docker resources; refusing to reuse it"
  for service_name in "${proof_services[@]}"; do
    assert_named_object_absent container "${proof_project}-${service_name}-1"
  done
  for volume_name in "${proof_volumes[@]}"; do
    assert_named_object_absent volume "${proof_project}_${volume_name}"
  done
  assert_named_object_absent network "${proof_project}_default"
  assert_named_object_absent image "${proof_control_image}"
  assert_named_object_absent image "${proof_seed_image}"
  assert_named_object_absent volume "${wrong_kek_volume}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
  printf 'AUD-68 proof: %s\n' "$*" >&2
  exit 1
}

prepare_private_file() {
  local path=$1
  : >"${path}"
  chmod 0600 "${path}"
}

loaded_token=""

load_token_file() {
  local path=$1
  local label=$2
  [[ -s "${path}" ]] || die "${label} did not mint a token"
  loaded_token="$(<"${path}")"
  [[ "${loaded_token}" =~ ^trst_[A-Za-z0-9_-]{43}$ ]] ||
    die "${label} returned a token outside the exact trst_ plus 32-byte base64url shape"
  cmp -s -- "${path}" <(printf '%s\n' "${loaded_token}") ||
    die "${label} token file contained trailing or non-token output"
}

assert_token_file() {
  local path=$1
  local label=$2
  local subject=$3
  load_token_file "${path}" "${label}"
  unset loaded_token
  assert_subject_scopes "${subject}"
}

mint_control_token() {
  local path=$1
  local subject=$2
  prepare_private_file "${path}"
  "${compose[@]}" exec -T trstctl /usr/local/bin/trstctl token create \
    --tenant "${tenant_id}" \
    --tenant-name "${tenant_name}" \
    --subject "${subject}" \
    --scopes "${read_scopes}" >"${path}"
  assert_token_file "${path}" "control container" "${subject}"
}

mint_admin_token() {
  local path=$1
  local subject=$2
  prepare_private_file "${path}"
  "${compose[@]}" run -T --rm --no-deps \
    --entrypoint /usr/local/bin/trstctl demo-seed token create \
    --tenant "${tenant_id}" \
    --tenant-name "${tenant_name}" \
    --subject "${subject}" \
    --scopes "${read_scopes}" >"${path}"
  assert_token_file "${path}" "admin container" "${subject}"
}

# curl receives the Authorization header through its stdin config. The bearer is
# never placed in argv, an environment variable, a log line, or terminal output.
assert_scoped_read() {
  local token_file=$1
  local label=$2
  local response_file="${proof_tmp}/${label}.json"
  local status
  local token
  prepare_private_file "${response_file}"
  artifacts+=("${response_file}")
  load_token_file "${token_file}" "${label}"
  token="${loaded_token}"
  unset loaded_token
  if ! status="$(
    printf 'header = "Authorization: Bearer %s"\n' "${token}" |
      curl --silent --show-error --cacert "${proof_tls_trust}" --config - \
        --output "${response_file}" --write-out '%{http_code}' "${api_url}"
  )"; then
    unset token
    die "${label} tenant-local certificate read failed"
  fi
  unset token
  [[ "${status}" == "200" ]] || die "${label} tenant-local certificate read returned HTTP ${status}"
  jq -e --arg tenant "${tenant_id}" '
    type == "object" and
    (.items | (type == "array" and length > 0)) and
    (.next_cursor | type == "string") and
    ([.items[] |
      (type == "object") and
      (.id | (type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) and
      (.tenant_id == $tenant) and
      (.subject | (type == "string" and length > 0)) and
      (.fingerprint | (type == "string" and test("^[0-9a-f]{64}$"))) and
      ((.status == "active") or (.status == "superseded") or (.status == "revoked"))
    ] | all)
  ' "${response_file}" >/dev/null ||
    die "${label} response was not the served certificate-list JSON shape"
}

# This is the durable authority that every `token create` invocation must replay.
# The protected result remains opaque; its length and SHA-256 digest let the proof
# detect any rewrite without exposing the retained bytes.
snapshot_registration_authority() {
  local query
  query="SELECT concat_ws('|',
    (SELECT count(*)::text FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT coalesce(max(name), '') FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT coalesce(max(event_seq), 0)::text FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT count(*)::text FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
       AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT coalesce(max(status), '') FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
       AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT coalesce(max(result_codec), '') FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
       AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT coalesce(max(request_binding), '') FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
       AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT coalesce(max(octet_length(result)), 0)::text FROM idempotency_keys
       WHERE tenant_id = '${tenant_id}'::uuid AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT coalesce(max(encode(sha256(result), 'hex')), '') FROM idempotency_keys
       WHERE tenant_id = '${tenant_id}'::uuid AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(tenant_id::text, name, created_at, event_seq) ORDER BY tenant_id)::text, '[]'), 'UTF8')), 'hex')
       FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(tenant_id::text, key, status, encode(result, 'hex'), created_at, completed_at, request_binding, result_codec) ORDER BY key)::text, '[]'), 'UTF8')), 'hex')
       FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
        AND key = 'bootstrap-tenant:${tenant_id}')
  );"
  "${compose[@]}" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U trstctl -d trstctl -Atq -c "${query}"
}

assert_registration_authority_ready() {
  local snapshot=$1
  local tenant_count name event_sequence registration_count status codec binding result_length result_digest
  local tenant_authority_digest registration_authority_digest
  IFS='|' read -r tenant_count name event_sequence registration_count status codec binding result_length result_digest tenant_authority_digest registration_authority_digest <<<"${snapshot}"
  [[ "${tenant_count}" == "1" && "${name}" == "${tenant_name}" ]] ||
    die "seed did not establish the exact demo tenant registration"
  [[ "${event_sequence}" =~ ^[1-9][0-9]*$ ]] ||
    die "seed registration lacks a positive immutable event sequence"
  [[ "${registration_count}" == "1" && "${status}" == "completed" && "${codec}" == "sealed-row-v1" ]] ||
    die "seed registration receipt is missing, incomplete, or not protected"
  [[ "${binding}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "seed registration receipt lacks its exact request binding"
  [[ "${result_length}" =~ ^[1-9][0-9]*$ && "${result_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    die "seed registration receipt lacks a protected result fingerprint"
  [[ "${tenant_authority_digest}" =~ ^[0-9a-f]{64}$ && "${registration_authority_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    die "seed registration receipt lacks exact tenant and idempotency-row authority digests"
}

assert_registration_authority_unchanged() {
  local label=$1
  local before=$2
  local after
  after="$(snapshot_registration_authority)"
  [[ "${after}" == "${before}" ]] ||
    die "${label} rewrote the fixed tenant-registration authority instead of replaying it exactly"
}

assert_subject_scopes() {
  local subject=$1
  local authority
  local query
  [[ "${subject}" =~ ^aud68-[a-z0-9-]+$ ]] || die "refusing unsafe proof subject for SQL scope check"
  query="SELECT concat_ws('|', count(*)::text, coalesce(max(array_to_string(scopes, ',')), ''))
           FROM api_tokens
          WHERE tenant_id = '${tenant_id}'::uuid AND subject = '${subject}';"
  authority="$("${compose[@]}" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U trstctl -d trstctl -Atq -c "${query}")"
  [[ "${authority}" == "1|${read_scopes}" ]] ||
    die "${subject} token row did not retain exactly the requested read-only scopes"
}

# PostgreSQL hashes canonical, ordered representations before returning them. The
# shell sees only counts and SHA-256 digests: neither token hashes nor protected
# idempotency-result bytes cross the database boundary. Every mutable column in
# the tenant, API-token, and fixed bootstrap-idempotency authority is included.
snapshot_sql_state() {
  local query
  query="SELECT concat_ws('|',
    (SELECT count(*)::text FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT count(*)::text FROM api_tokens WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT count(*)::text FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
       AND key = 'bootstrap-tenant:${tenant_id}'),
    (SELECT count(*)::text FROM api_tokens WHERE tenant_id = '${tenant_id}'::uuid
       AND subject IN ('aud68-wrong-custody', 'aud68-missing-custody')),
    (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(tenant_id::text, name, created_at, event_seq) ORDER BY tenant_id)::text, '[]'), 'UTF8')), 'hex')
       FROM tenants WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(id::text, tenant_id::text, token_hash, subject, subject_ref, scopes, expires_at, created_at, revoked_at, revoked_by, revocation_reason) ORDER BY id)::text, '[]'), 'UTF8')), 'hex')
       FROM api_tokens WHERE tenant_id = '${tenant_id}'::uuid),
    (SELECT encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(tenant_id::text, key, status, encode(result, 'hex'), created_at, completed_at, request_binding, result_codec) ORDER BY key)::text, '[]'), 'UTF8')), 'hex')
       FROM idempotency_keys WHERE tenant_id = '${tenant_id}'::uuid
        AND key = 'bootstrap-tenant:${tenant_id}')
  );"
  "${compose[@]}" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U trstctl -d trstctl -Atq -c "${query}"
}

# Stop the control plane before using this snapshot. That removes legitimate
# background appenders, making an exact all-event-stream head comparison meaningful.
snapshot_event_head() {
  "${compose[@]}" run -T --rm --no-deps --entrypoint node demo-seed -e '
    (async () => {
      const response = await fetch("http://nats:8222/jsz?streams=true");
      if (!response.ok) throw new Error(`JetStream monitor returned ${response.status}`);
      const payload = await response.json();
      const accounts = Array.isArray(payload.account_details) ? payload.account_details : [];
      const streams = accounts.flatMap((account) =>
        Array.isArray(account.stream_detail) ? account.stream_detail : [])
        .filter((stream) => String(stream.name || "").startsWith("TRSTCTL_EVENTS"));
      if (streams.length === 0) throw new Error("no trstctl event stream found");
      const parts = streams.map((stream) => {
        const state = stream.state || {};
        for (const key of ["messages", "first_seq", "last_seq"]) {
          if (!Number.isSafeInteger(state[key])) throw new Error(`stream ${stream.name} lacks ${key}`);
        }
        return [stream.name, state.messages, state.first_seq, state.last_seq].join(":");
      }).sort();
      process.stdout.write(parts.join(","));
    })().catch((error) => {
      console.error(`AUD-68 proof: ${error.message}`);
      process.exit(1);
    });
  '
}

assert_state_unchanged() {
  local label=$1
  local before_sql=$2
  local before_event_head=$3
  local after_sql
  local after_event_head
  after_sql="$(snapshot_sql_state)"
  after_event_head="$(snapshot_event_head)"
  [[ "${after_sql}" == "${before_sql}" ]] ||
    die "${label} changed tenant, token, or registration-authority state"
  [[ "${after_event_head}" == "${before_event_head}" ]] ||
    die "${label} changed the immutable event-stream head"
}

expect_custody_failure() {
  local label=$1
  local expected_error=$2
  local stdout_file=$3
  local stderr_file=$4
  shift 4
  prepare_private_file "${stdout_file}"
  prepare_private_file "${stderr_file}"
  if "$@" >"${stdout_file}" 2>"${stderr_file}"; then
    die "${label} unexpectedly minted a token"
  fi
  [[ ! -s "${stdout_file}" ]] || die "${label} wrote credential bytes while failing"
  grep -Fq -- "${expected_error}" "${stderr_file}" ||
    die "${label} did not fail at the expected custody boundary"
}

for required in docker curl jq cmp; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
docker compose version >/dev/null
docker compose wait --help >/dev/null
compose_up_help="$(docker compose up --help)"
[[ "${compose_up_help}" == *"--wait-timeout"* ]] || die "Docker Compose must support up --wait-timeout"
unset compose_up_help
docker info >/dev/null
[[ -f "${compose_file}" ]] || die "compose file is missing: ${compose_file}"
[[ -d "${repo_root}/internal" ]] || die "run this proof from a trstctl source checkout"
assert_project_is_fresh
proof_namespace_owned=1

control_before_token="${proof_tmp}/control-before.token"
admin_before_token="${proof_tmp}/admin-before.token"
control_after_token="${proof_tmp}/control-after.token"
admin_after_token="${proof_tmp}/admin-after.token"
wrong_stdout="${proof_tmp}/wrong-custody.stdout"
wrong_stderr="${proof_tmp}/wrong-custody.stderr"
missing_stdout="${proof_tmp}/missing-custody.stdout"
missing_stderr="${proof_tmp}/missing-custody.stderr"
proof_tls_trust="${proof_tmp}/control-plane.crt"
artifacts+=(
  "${control_before_token}" "${admin_before_token}"
  "${control_after_token}" "${admin_after_token}"
  "${wrong_stdout}" "${wrong_stderr}" "${missing_stdout}" "${missing_stderr}" "${proof_tls_trust}"
)

printf 'AUD-68 proof: starting fresh isolated project %s\n' "${proof_project}"
proof_started=1
"${compose[@]}" up -d --build
"${compose[@]}" wait demo-seed
"${compose[@]}" up -d --wait --wait-timeout 120 signer trstctl
"${compose[@]}" cp trstctl:/public-trust/control-plane.crt "${proof_tls_trust}"
chmod 0600 "${proof_tls_trust}"

registration_authority="$(snapshot_registration_authority)"
assert_registration_authority_ready "${registration_authority}"
mint_control_token "${control_before_token}" "aud68-control-before-restart"
assert_registration_authority_unchanged "control-container replay before restart" "${registration_authority}"
mint_admin_token "${admin_before_token}" "aud68-admin-before-restart"
assert_registration_authority_unchanged "admin-container replay before restart" "${registration_authority}"
assert_scoped_read "${control_before_token}" "control-before-restart"
assert_scoped_read "${admin_before_token}" "admin-before-restart"

# Freeze ordinary appenders, then prove two broken admin custody configurations
# fail before changing the event head, tenant registration authority, or token rows.
"${compose[@]}" stop trstctl
before_sql="$(snapshot_sql_state)"
before_event_head="$(snapshot_event_head)"

# Build a deliberately different but structurally valid KEK in its own exact,
# proof-namespaced volume. This is deliberately a standalone, networkless Docker
# run rather than `compose run`: it mounts only the new volume and cannot see the
# deployment KEK, signer authorization secret, audit data, UDS, or signer keys.
docker volume create \
  --label "com.docker.compose.project=${proof_project}" \
  --label "trstctl.audit-proof=AUD-68" \
  "${wrong_kek_volume}" >/dev/null
wrong_kek_volume_created=1
docker run --rm --network none --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --user 65532:65532 \
  --mount "type=volume,src=${wrong_kek_volume},dst=/tmp" \
  --entrypoint /bin/sh "${proof_seed_image}" -eu -c '
    umask 077
    head -c 32 /dev/urandom > /tmp/kek.bin
    chmod 0600 /tmp/kek.bin
    test "$(wc -c < /tmp/kek.bin)" -eq 32
    test "$(stat -c %u:%g /tmp/kek.bin)" = "65532:65532"
    test "$(stat -c %a /tmp/kek.bin)" = "600"
  '

expect_custody_failure \
  "wrong read-only custody mount" "seal: decrypt failed" \
  "${wrong_stdout}" "${wrong_stderr}" \
  "${compose[@]}" run -T --rm --no-deps \
    --volume "${wrong_kek_volume}:/wrong-kek:ro" \
    -e TRSTCTL_SECRETS_KEK_FILE=/wrong-kek/kek.bin \
    --entrypoint /usr/local/bin/trstctl demo-seed token create \
    --tenant "${tenant_id}" --tenant-name "${tenant_name}" \
    --subject aud68-wrong-custody --scopes "${read_scopes}"
assert_state_unchanged "wrong read-only custody mount" "${before_sql}" "${before_event_head}"

expect_custody_failure \
  "missing deployment KEK" "bootstrap: provision credential KEK" \
  "${missing_stdout}" "${missing_stderr}" \
  "${compose[@]}" run -T --rm --no-deps \
    -e TRSTCTL_SECRETS_KEK_FILE=/data/secrets/aud68-missing-kek.bin \
    --entrypoint /usr/local/bin/trstctl demo-seed token create \
    --tenant "${tenant_id}" --tenant-name "${tenant_name}" \
    --subject aud68-missing-custody --scopes "${read_scopes}"
assert_state_unchanged "missing deployment KEK" "${before_sql}" "${before_event_head}"

# The control process was stopped above and the signer is restarted here. Starting
# control only after the signer is running gives both processes a clean restart
# while preserving every proof-project volume.
"${compose[@]}" restart signer
if ! "${compose[@]}" up -d --wait --wait-timeout 120 signer trstctl; then
  docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} error={{json .State.Error}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "${proof_project}-trstctl-1" >&2 || true
  docker logs --tail 120 "${proof_project}-trstctl-1" 2>&1 |
    sed -E \
      -e 's/trst_[A-Za-z0-9_-]{43}/[REDACTED_TOKEN]/g' \
      -e 's#(postgres://[^:/@]+:)[^@[:space:]]+@#\1[REDACTED]@#g' >&2 || true
  die "control did not become healthy after the signer/control restart"
fi
assert_registration_authority_unchanged "control and signer restart" "${registration_authority}"

# Previously minted credentials must remain readable, and both execution images
# must still replay the fixed registration receipt and mint usable narrow tokens.
assert_subject_scopes "aud68-control-before-restart"
assert_subject_scopes "aud68-admin-before-restart"
assert_scoped_read "${control_before_token}" "control-token-after-restart"
assert_scoped_read "${admin_before_token}" "admin-token-after-restart"
mint_control_token "${control_after_token}" "aud68-control-after-restart"
assert_registration_authority_unchanged "control-container replay after restart" "${registration_authority}"
mint_admin_token "${admin_after_token}" "aud68-admin-after-restart"
assert_registration_authority_unchanged "admin-container replay after restart" "${registration_authority}"
assert_scoped_read "${control_after_token}" "control-after-restart"
assert_scoped_read "${admin_after_token}" "admin-after-restart"

printf 'AUD-68 proof passed: shared custody, exact replay, scoped reads, restart durability, and zero-effect refusal\n'
