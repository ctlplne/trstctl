#!/bin/sh
set -eu

lab_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$lab_dir/../../.." && pwd)"
lab_project="${TRSTCTL_LAB_PROJECT:-trstctl-partner-lab}"
case "$lab_project" in
  ""|[!a-z0-9]*|*[!a-z0-9_-]*)
    printf '%s\n' "TRSTCTL_LAB_PROJECT must be a lowercase Compose project name." >&2
    exit 2
    ;;
esac

token_file="${TRSTCTL_LAB_CUSTOMER_TOKEN_FILE:-}"
if [ -z "$token_file" ] || [ ! -f "$token_file" ] || [ ! -r "$token_file" ] || [ ! -s "$token_file" ]; then
  printf '%s\n' "Set TRSTCTL_LAB_CUSTOMER_TOKEN_FILE to the customer's readable, nonempty 0600 API token file." >&2
  exit 2
fi
if token_mode="$(stat -c '%a' "$token_file" 2>/dev/null)"; then
  :
elif token_mode="$(stat -f '%Lp' "$token_file" 2>/dev/null)"; then
  :
else
  printf '%s\n' "Cannot check the customer token file permissions." >&2
  exit 2
fi
case "$token_mode" in
  600|400) ;;
  *) printf '%s\n' "Customer token file must have mode 0600 or 0400." >&2; exit 2 ;;
esac
# Compose resolves relative bind paths from its first configuration file, not
# the caller's directory. Resolve the supplied file before handing it to Compose.
token_dir="$(CDPATH= cd -- "$(dirname -- "$token_file")" && pwd)"
TRSTCTL_LAB_CUSTOMER_TOKEN_FILE="$token_dir/$(basename -- "$token_file")"
export TRSTCTL_LAB_CUSTOMER_TOKEN_FILE

compose() {
  docker compose -p "$lab_project" \
    -f "$repo_dir/deploy/demo/docker-compose.yml" -f "$lab_dir/docker-compose.yml" \
    --profile partner-lab --profile partner-lab-customer "$@"
}

# Read-only checks: a follow-up enrollment must never start, rebuild, or
# reconcile the existing control plane, signer, license, or front doors.
for service in trstctl frontdoors-lab; do
  service_id="$(compose ps --status running -q "$service")"
  case "$service_id" in
    ""|*[!a-f0-9]*)
      printf '%s\n' "Customer enrollment needs exactly one running $service in $lab_project. Start that lab first with deploy/demo/lab/run.sh." >&2
      exit 1
      ;;
  esac
done

seed_image="${TRSTCTL_DEMO_SEED_IMAGE:-${lab_project}-seed:local}"
if ! seed_id="$(docker image inspect --format '{{.Id}}' "$seed_image")"; then
  printf '%s\n' "The installed lab helper image is missing. Start this project first, or set TRSTCTL_DEMO_SEED_IMAGE to the override used at startup." >&2
  exit 1
fi
# Pin the one-shot helper to the inspected local image; do not pull or build.
TRSTCTL_DEMO_SEED_IMAGE="$seed_id"
export TRSTCTL_DEMO_SEED_IMAGE
compose run --rm --no-deps --pull never lab-customer-enroll
