#!/usr/bin/env bash
# check-base-pinned.sh — enforce that the production container image is built on a
# DIGEST-pinned base, never a floating tag (SF.1: "pin base images by digest, not
# tag"). A floating tag means the released artifact is not reproducible and can
# silently inherit a vulnerable base; this guard fails CI if that regresses.
#
# Two pure checks, each unit-tested by check-base-pinned_selftest.sh:
#   - the Dockerfile runtime stage builds FROM the injectable ${BASE_IMAGE} arg
#     (so the release pipeline can substitute a digest), not a hardcoded tag;
#   - the release workflow actually resolves a @sha256 digest and passes it as
#     BASE_IMAGE.
set -euo pipefail

# runtime_from_uses_arg <dockerfile>
# True (0) iff the LAST `FROM` (the runtime stage) references ${BASE_IMAGE}.
runtime_from_uses_arg() {
	local df="$1" last
	last="$(grep -E '^[[:space:]]*FROM[[:space:]]' "$df" | tail -1)"
	[[ "$last" == *'${BASE_IMAGE}'* || "$last" == *'$BASE_IMAGE'* ]]
}

# workflow_resolves_digest <workflow>
# True (0) iff the workflow resolves an image digest and feeds it to BASE_IMAGE.
workflow_resolves_digest() {
	local wf="$1"
	grep -qE 'Manifest\.Digest|@sha256:|@\$\{?digest' "$wf" && grep -qE 'BASE_IMAGE=' "$wf"
}

main() {
	local root="${1:-.}"
	local df="${root}/deploy/docker/Dockerfile"
	local release="${root}/.github/workflows/release.yml"
	local rc=0

	if runtime_from_uses_arg "$df"; then
		echo "ok:   Dockerfile runtime stage builds FROM \${BASE_IMAGE} (injectable)"
	else
		echo "FAIL: Dockerfile runtime FROM is a hardcoded base — must use \${BASE_IMAGE} so the release pipeline can pin a digest ($df)"
		rc=1
	fi

	if workflow_resolves_digest "$release"; then
		echo "ok:   release workflow resolves a @sha256 digest and passes it as BASE_IMAGE"
	else
		echo "FAIL: release workflow does not resolve a digest for BASE_IMAGE — the released image would float on a tag ($release)"
		rc=1
	fi

	return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
