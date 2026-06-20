#!/usr/bin/env bash
# check-base-pinned.sh — enforce that the production container image is built on a
# DIGEST-pinned base, never a floating tag (SF.1: "pin base images by digest, not
# tag"). A floating tag means the released artifact is not reproducible and can
# silently inherit a vulnerable base; this guard fails CI if that regresses.
#
# Three pure checks, each unit-tested by check-base-pinned_selftest.sh:
#   - the Dockerfile build stage builds FROM the injectable ${BUILD_IMAGE} arg;
#   - the Dockerfile runtime stage builds FROM the injectable ${BASE_IMAGE} arg;
#   - the release workflow resolves @sha256 digests and passes them as
#     BUILD_IMAGE and BASE_IMAGE.
set -euo pipefail

# build_from_uses_arg <dockerfile>
# True (0) iff the FIRST `FROM` (the build stage) references ${BUILD_IMAGE}.
build_from_uses_arg() {
	local df="$1" first
	first="$(grep -E '^[[:space:]]*FROM[[:space:]]' "$df" | head -1)"
	[[ "$first" == *'${BUILD_IMAGE}'* || "$first" == *'$BUILD_IMAGE'* ]]
}

# runtime_from_uses_arg <dockerfile>
# True (0) iff the LAST `FROM` (the runtime stage) references ${BASE_IMAGE}.
runtime_from_uses_arg() {
	local df="$1" last
	last="$(grep -E '^[[:space:]]*FROM[[:space:]]' "$df" | tail -1)"
	[[ "$last" == *'${BASE_IMAGE}'* || "$last" == *'$BASE_IMAGE'* ]]
}

# workflow_resolves_digest <workflow>
# True (0) iff the workflow resolves image digests and feeds them to both
# BUILD_IMAGE and BASE_IMAGE.
workflow_resolves_digest() {
	local wf="$1"
	grep -qE 'Manifest\.Digest|@sha256:|@\$\{?digest' "$wf" &&
		grep -qE 'BUILD_IMAGE=' "$wf" &&
		grep -qE 'BASE_IMAGE=' "$wf"
}

main() {
	local root="${1:-.}"
	local df="${root}/deploy/docker/Dockerfile"
	local release="${root}/.github/workflows/release.yml"
	local rc=0

	if build_from_uses_arg "$df"; then
		echo "ok:   Dockerfile build stage builds FROM \${BUILD_IMAGE} (injectable)"
	else
		echo "FAIL: Dockerfile build FROM is a hardcoded base — must use \${BUILD_IMAGE} so the release pipeline can pin a digest ($df)"
		rc=1
	fi

	if runtime_from_uses_arg "$df"; then
		echo "ok:   Dockerfile runtime stage builds FROM \${BASE_IMAGE} (injectable)"
	else
		echo "FAIL: Dockerfile runtime FROM is a hardcoded base — must use \${BASE_IMAGE} so the release pipeline can pin a digest ($df)"
		rc=1
	fi

	if workflow_resolves_digest "$release"; then
		echo "ok:   release workflow resolves @sha256 digests and passes BUILD_IMAGE/BASE_IMAGE"
	else
		echo "FAIL: release workflow does not resolve digests for BUILD_IMAGE and BASE_IMAGE — the released image would float on a tag ($release)"
		rc=1
	fi

	return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
