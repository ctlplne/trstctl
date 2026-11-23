#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
cat >"$tmp/public.pem" <<'PEM'
-----BEGIN PUBLIC KEY-----
AQID
-----END PUBLIC KEY-----
PEM
cat >"$tmp/docker" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
if args[:3] != ["compose", "-f", "fixture.yml"]:
    raise SystemExit("unexpected compose invocation")
if args[3] == "cp":
    if args[4] != "trstctl:/data/signer/keys/agid-control-plane/reachability-verdict-v1.pub":
        raise SystemExit("wrong public key source")
    shutil.copyfile(os.environ["AGID_FIXTURE_PUBLIC"], args[5])
elif args[3] == "run":
    if args[args.index("--entrypoint") + 1] != "/usr/local/bin/trstctl-signer" or "--no-deps" not in args:
        raise SystemExit("signer one-shot entrypoint or dependency fence is missing")
    mount = args[args.index("-v") + 1]
    path, dest, mode = mount.split(":")
    if dest != "/runtime/agentid-verdict-trust.json" or mode != "ro":
        raise SystemExit("binding was not mounted read-only")
    binding = json.loads(Path(path).read_text())
    if binding != {"kind": "reachability_key", "key_id": "agentid-reach-verdict",
                   "public_key_pem": Path(os.environ["AGID_FIXTURE_PUBLIC"]).read_text()}:
        raise SystemExit("binding changed the control-plane public key")
    if args[-2:] != ["--keystore=/data/signer/keys", "--agid-provision-trust=/runtime/agentid-verdict-trust.json"]:
        raise SystemExit("signer one-shot was not selected")
    Path(os.environ["AGID_FIXTURE_CALLED"]).write_text("yes")
else:
    raise SystemExit("unexpected docker operation")
PY
chmod 0755 "$tmp/docker"
AGID_FIXTURE_PUBLIC="$tmp/public.pem" AGID_FIXTURE_CALLED="$tmp/called" \
  PATH="$tmp:$PATH" bash "$root/scripts/ci/provision-compose-agid-verdict.sh" fixture.yml
test "$(cat "$tmp/called")" = yes
printf 'compose AGID verdict trust ceremony: passed\n'
