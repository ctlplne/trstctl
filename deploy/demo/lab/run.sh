#!/bin/sh
set -u

lab_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$lab_dir/../../.." && pwd)"
lab_project="${TRSTCTL_LAB_PROJECT:-trstctl-partner-lab}"
run_dod="${TRSTCTL_LAB_RUN_DOD:-1}"
run_journeys="${TRSTCTL_LAB_RUN_JOURNEYS:-1}"
case "$lab_project" in
  ""|[!a-z0-9]*|*[!a-z0-9_-]*)
    printf '%s\n' "TRSTCTL_LAB_PROJECT must start with a lowercase letter or digit and contain only lowercase letters, digits, underscores, or hyphens." >&2
    exit 2
    ;;
esac
case "$run_dod" in
  0|1) ;;
  *)
    printf '%s\n' "TRSTCTL_LAB_RUN_DOD must be 0 (live repair loop) or 1 (full qualification)." >&2
    exit 2
    ;;
esac
case "$run_journeys" in
  0|1) ;;
  *)
    printf '%s\n' "TRSTCTL_LAB_RUN_JOURNEYS must be 0 (start only; drive it yourself) or 1 (run the automated journeys)." >&2
    exit 2
    ;;
esac
# Every retained project owns its image tags. BuildKit layers remain shared, so
# this costs only changed layers and small manifests, while a later repair build
# cannot delete the image identity an earlier definition-of-done proof is still
# inspecting through the Docker socket.
TRSTCTL_DEMO_CONTROL_IMAGE="${TRSTCTL_DEMO_CONTROL_IMAGE:-${lab_project}-control:local}"
TRSTCTL_DEMO_SEED_IMAGE="${TRSTCTL_DEMO_SEED_IMAGE:-${lab_project}-seed:local}"
TRSTCTL_DEMO_FRONTDOORS_IMAGE="${TRSTCTL_DEMO_FRONTDOORS_IMAGE:-${lab_project}-frontdoors:local}"
lab_head="$(git -C "$repo_dir" rev-parse --verify HEAD 2>/dev/null || printf '%s' none)"
lab_commit="${TRSTCTL_LAB_BUILD_COMMIT:-$lab_head}"
if [ -z "${TRSTCTL_LAB_BUILD_COMMIT:-}" ] && [ -n "$(git -C "$repo_dir" status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
  # A repair-loop image is allowed, but it must not impersonate the clean HEAD.
  # Once the repair is committed, this marker disappears on the next rebuild.
  lab_commit="dirty-$lab_head"
fi
lab_short="$(printf '%s' "$lab_commit" | cut -c1-12)"
TRSTCTL_LAB_BUILD_COMMIT="$lab_commit"
TRSTCTL_LAB_BUILD_VERSION="${TRSTCTL_LAB_BUILD_VERSION:-dev-$lab_short}"
TRSTCTL_LAB_BUILD_DATE="${TRSTCTL_LAB_BUILD_DATE:-$(git -C "$repo_dir" show -s --format=%cI "$lab_head" 2>/dev/null || printf '%s' 1970-01-01T00:00:00Z)}"
export TRSTCTL_DEMO_CONTROL_IMAGE TRSTCTL_DEMO_SEED_IMAGE TRSTCTL_DEMO_FRONTDOORS_IMAGE
export TRSTCTL_LAB_BUILD_COMMIT TRSTCTL_LAB_BUILD_VERSION TRSTCTL_LAB_BUILD_DATE
compose="docker compose -p $lab_project -f $repo_dir/deploy/demo/docker-compose.yml -f $lab_dir/docker-compose.yml --profile partner-lab"

live_status=0
census_status=0

# Start namespace owners before the loopback helpers that join them. Creating
# both in one parallel `compose up` can race Docker's network-namespace mount on
# busy workstations. This staged order is safe to rerun and preserves volumes.
$compose build trstctl demo-seed || exit $?
# frontdoors-lab copies the edge collector out of the just-built control image.
# Build it second so a parallel BuildKit solve cannot reuse an older local tag.
$compose build frontdoors-lab || exit $?
$compose up -d postgres nats localstack pebble-challtestsrv pebble managedkeys-config oidc-keys lab-init || exit $?
$compose up -d --no-deps signer || exit $?
$compose up -d --no-deps localstack-signer-loopback || exit $?
$compose up -d --no-deps trstctl || exit $?

healthy=false
attempt=0
while [ "$attempt" -lt 120 ]; do
  if curl -ksSf https://127.0.0.1:9443/healthz >/dev/null 2>&1; then healthy=true; break; fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$healthy" != true ]; then
  printf '%s\n' "Partner lab control plane did not become healthy within 120 seconds." >&2
  exit 1
fi

$compose up -d --no-deps demo-oidc || exit $?
$compose up -d --no-deps localstack-loopback oidc-loopback pebble-loopback dns-webhook-loopback alert-sink || exit $?
$compose run --rm --no-deps demo-seed || exit $?
$compose run --rm --no-deps lab-bootstrap || exit $?
$compose up -d --no-deps frontdoors-lab || exit $?
if [ "$run_journeys" -eq 1 ]; then
  $compose run --rm --no-deps lab-runner || live_status=$?
else
  # Start only: the CA, DNS challenge server, alert receiver, front doors, and
  # the DNS-01 provider config are ready, but no listener certificate has been
  # touched. Drive the lifecycle yourself from the console.
  printf '%s\n' "Partner lab started without the automated journeys (TRSTCTL_LAB_RUN_JOURNEYS=0)."
  printf '%s\n' "Console: https://127.0.0.1:9443 (trust the published certificate first; see docs/local-evaluation-tls.md)."
  printf '%s\n' "Listeners keep their self-signed baseline until you issue through the console."
  run_dod=0
fi

cd "$repo_dir" || exit 1
census_out="/private/tmp/${lab_project}-connector-census.json"
if [ "$run_dod" -eq 1 ]; then
  dod_cache_parent="/private/tmp/${lab_project}-dod-cache"
  dod_cache="$dod_cache_parent/go-build"
  # The DoD runner rejects a private cache whose immediate parent is the shared
  # 01777 /private/tmp directory. Give each retained lab a dedicated 0700 parent,
  # then mount only its child cache. This is a security boundary, not a warning:
  # another local user must not be able to swap compiled objects under the census.
  if [ ! -e "$dod_cache" ]; then (umask 077; mkdir -p "$dod_cache"); fi
  chmod 0700 "$dod_cache_parent" "$dod_cache" || exit $?
  TRSTCTL_DOD_GOCACHE="$dod_cache" \
    DOD_CENSUS_OUT="$census_out" make dod-gate || census_status=$?
else
  census_out="deferred by TRSTCTL_LAB_RUN_DOD=0; run the default profile before qualification"
fi

printf '%s\n' "Partner lab remains running; named volumes and evidence were retained."
printf '%s\n' "Live substrate journey status: $live_status"
printf '%s\n' "Definition-of-done census status: $census_status"
printf '%s\n' "Connector census evidence: $census_out"

if [ "$live_status" -ne 0 ] || [ "$census_status" -ne 0 ]; then exit 1; fi
