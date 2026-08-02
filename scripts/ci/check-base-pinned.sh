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
#
# The two Dockerfile stages are selected BY NAME ('AS build' / 'AS runtime'), never
# by position. Positional selection (first FROM / last FROM) rotted silently once
# the Dockerfile grew a leading 'FROM scratch AS context-audit' audit stage and a
# trailing 'FROM runtime AS demo' stage: the guard then inspected two stages it
# does not document and failed unconditionally, which guards nothing.
set -euo pipefail

# from_stage_line <dockerfile> <stage>
# Echo the single `FROM ... AS <stage>` line. Returns 1 and echoes nothing unless
# EXACTLY ONE such stage exists, so deleting, renaming, or duplicating the stage is
# a loud failure rather than a silent pass. A trailing `# ...` comment is tolerated.
from_stage_line() {
	local df="$1" stage="$2" lines count
	lines="$(grep -iE "^[[:space:]]*FROM[[:space:]].*[[:space:]]AS[[:space:]]+${stage}[[:space:]]*(#.*)?\$" "$df" 2>/dev/null || true)"
	count="$(printf '%s' "$lines" | grep -c '[^[:space:]]' || true)"
	[[ "$count" -eq 1 ]] || return 1
	printf '%s\n' "$lines"
}

# build_from_uses_arg <dockerfile>
# True (0) iff the stage NAMED `build` exists exactly once and references
# ${BUILD_IMAGE}.
build_from_uses_arg() {
	local df="$1" line
	line="$(from_stage_line "$df" build)" || return 1
	[[ "$line" == *'${BUILD_IMAGE}'* || "$line" == *'$BUILD_IMAGE'* ]]
}

# runtime_from_uses_arg <dockerfile>
# True (0) iff the stage NAMED `runtime` exists exactly once and references
# ${BASE_IMAGE}.
runtime_from_uses_arg() {
	local df="$1" line
	line="$(from_stage_line "$df" runtime)" || return 1
	[[ "$line" == *'${BASE_IMAGE}'* || "$line" == *'$BASE_IMAGE'* ]]
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

	if ! from_stage_line "$df" build >/dev/null; then
		echo "FAIL: Dockerfile has no unique 'FROM ... AS build' stage — the base-pin guard cannot be evaluated; do not rename, remove, or duplicate the build stage ($df)"
		rc=1
	elif build_from_uses_arg "$df"; then
		echo "ok:   Dockerfile build stage builds FROM \${BUILD_IMAGE} (injectable)"
	else
		echo "FAIL: Dockerfile build FROM is a hardcoded base — must use \${BUILD_IMAGE} so the release pipeline can pin a digest ($df)"
		rc=1
	fi

	if ! from_stage_line "$df" runtime >/dev/null; then
		echo "FAIL: Dockerfile has no unique 'FROM ... AS runtime' stage — the base-pin guard cannot be evaluated; do not rename, remove, or duplicate the runtime stage ($df)"
		rc=1
	elif runtime_from_uses_arg "$df"; then
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
