#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Resolve an external base image to a digest and REQUIRE it to match the digest
# committed in .github/base-image-digests.env (SUPPLY-001).
#
# The release workflow used to resolve a floating tag at build time and check only
# that the result looked like a digest. That validates shape, not identity: if the
# upstream tag is repointed between releases, the release silently builds on a
# different image and every attestation faithfully attests the wrong thing. This
# turns a base-image change into a pull request, which is what it should be.
#
# Usage: resolve-pinned-base.sh <image-ref> <pin-key> <output-prefix>
#   image-ref     e.g. node:22-bookworm-slim
#   pin-key       e.g. NODE_22_BOOKWORM_SLIM
#   output-prefix e.g. node   (emits "<prefix>@sha256:..." as the ref)
#
# Prints "<name>@<digest>" on stdout. Exits non-zero, loudly and with the exact
# line to commit, when the pin is missing or does not match.
set -euo pipefail

image_ref="${1:?image ref required}"
pin_key="${2:?pin key required}"
output_prefix="${3:?output prefix required}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pin_file="${repo_root}/.github/base-image-digests.env"

resolved="$(docker buildx imagetools inspect "${image_ref}" --format '{{.Manifest.Digest}}')"
if [[ ! "${resolved}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
	echo "resolve-pinned-base: ${image_ref} resolved to something that is not a digest: ${resolved}" >&2
	exit 1
fi

if [[ ! -f "${pin_file}" ]]; then
	echo "resolve-pinned-base: ${pin_file} is missing; the release must not build on unpinned bases" >&2
	exit 1
fi

# Read the pin without sourcing the file, so a stray line cannot execute.
pinned="$(grep -E "^${pin_key}=" "${pin_file}" | tail -n1 | cut -d= -f2- || true)"

if [[ -z "${pinned}" ]]; then
	cat >&2 <<-EOF
		resolve-pinned-base: no pin recorded for ${image_ref}.

		It currently resolves to:
		    ${resolved}

		Verify that is the image you expect -- read the upstream release notes, do
		not just re-run until it is green -- then commit this line to
		.github/base-image-digests.env:

		    ${pin_key}=${resolved}
	EOF
	exit 1
fi

if [[ "${pinned}" != "${resolved}" ]]; then
	cat >&2 <<-EOF
		resolve-pinned-base: ${image_ref} HAS MOVED.

		    pinned:   ${pinned}
		    resolved: ${resolved}

		The upstream tag now points at a different image than the one this release
		was reviewed against. Do not update the pin to make the build pass without
		establishing why it moved. When the change is understood and intended,
		commit:

		    ${pin_key}=${resolved}
	EOF
	exit 1
fi

echo "${output_prefix}@${resolved}"
