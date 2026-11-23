#!/usr/bin/env bash
# CI acts as the eval-stack operator: export the control plane's public AGID
# verdict key, then install that exact public key in the isolated signer floor.
# The control plane cannot provision signer trust over RPC. Production operators
# must review and install the binding themselves.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <compose-file>" >&2
  exit 2
fi
compose_file="$1"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
public="$tmp/reachability-verdict-v1.pub"
binding="$tmp/agentid-verdict-trust.json"
compose=(docker compose -f "$compose_file")

# The first control-plane boot intentionally fails closed until the signer
# operator installs this trust. It has already sealed the private half and
# published only the public half on its own volume.
for attempt in {1..30}; do
  if "${compose[@]}" cp trstctl:/data/signer/keys/agid-control-plane/reachability-verdict-v1.pub "$public" >"$tmp/copy.log" 2>&1; then
    break
  fi
  if (( attempt == 30 )); then
    cat "$tmp/copy.log" >&2
    echo "control plane did not publish its AGID verdict public key" >&2
    exit 1
  fi
  sleep 2
done

python3 - "$public" "$binding" <<'PY'
import json
from pathlib import Path
import sys

public = Path(sys.argv[1]).read_text()
if not public.startswith("-----BEGIN PUBLIC KEY-----\n") or not public.endswith("-----END PUBLIC KEY-----\n"):
    raise SystemExit("control plane did not export a canonical public key PEM")
Path(sys.argv[2]).write_text(json.dumps({
    "kind": "reachability_key",
    "key_id": "agentid-reach-verdict",
    "public_key_pem": public,
}))
PY
# Public-only JSON must be readable by the signer's fixed nonroot uid.
chmod 0644 "$binding"
"${compose[@]}" run --rm --no-deps \
  -v "$binding:/runtime/agentid-verdict-trust.json:ro" \
  --entrypoint /usr/local/bin/trstctl-signer signer \
  --keystore=/data/signer/keys \
  --agid-provision-trust=/runtime/agentid-verdict-trust.json
