#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Build the source-ready provider into an isolated Terraform/OpenTofu mirror.
# This never changes ~/.terraformrc or another project configuration.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-directory>" >&2
  exit 2
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$1"
output="$(cd "$1" && pwd)"
version="${TRSTCTL_PROVIDER_VERSION:-0.1.0}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "TRSTCTL_PROVIDER_VERSION must be a three-part release version" >&2
  exit 2
fi

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
mirror="$output/mirror"
provider_dir="$mirror/registry.terraform.io/trstctl/trstctl/$version/${goos}_${goarch}"
mkdir -p "$provider_dir"
binary="$provider_dir/terraform-provider-trstctl_v$version"
CGO_ENABLED=0 go -C "$repo/clients/terraform" build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X trstctl.com/terraform-provider/internal/version.version=v$version" \
  -o "$binary" .

python3 - "$output" "$mirror" "$version" <<'PY'
import json
import pathlib
import sys

output, mirror, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
(output / "trstctl.tfrc").write_text(
    "provider_installation {\n"
    "  filesystem_mirror {\n"
    f"    path = {json.dumps(mirror)}\n"
    '    include = ["registry.terraform.io/trstctl/trstctl"]\n'
    "  }\n"
    "  direct {\n"
    '    exclude = ["registry.terraform.io/trstctl/trstctl"]\n'
    "  }\n"
    "}\n"
)
(output / "required_providers.tf.example").write_text(
    "terraform {\n"
    "  required_providers {\n"
    "    trstctl = {\n"
    '      source  = "registry.terraform.io/trstctl/trstctl"\n'
    f'      version = "{version}"\n'
    "    }\n"
    "  }\n"
    "}\n"
)
PY

printf 'Built %s\n' "$binary"
printf 'Copy %s into your Terraform project.\n' "$output/required_providers.tf.example"
printf 'From that project, run:\n  TF_CLI_CONFIG_FILE=%q terraform init\n' "$output/trstctl.tfrc"
printf 'OpenTofu users can replace terraform with tofu.\n'
