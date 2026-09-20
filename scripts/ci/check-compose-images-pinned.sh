#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# check-compose-images-pinned.sh — enforce that every third-party container image
# the shipped deploy/ stacks reference is pinned by an immutable @sha256 digest,
# never a floating tag (SUPPLY-008). deploy/docker/docker-compose.yml already
# states the rule in a comment ("Pinned by digest, not a floating tag ... cannot
# silently inherit a changed/ vulnerable image"), but until this guard existed
# SUPPLY-008 had no enforcement, and deploy/demo drifted to eight floating tags
# while sitting next to the file that documents the policy.
#
# Complements the two pin guards that already exist:
#   - check-base-pinned.sh    — the PRODUCTION image's build/runtime bases;
#   - check-actions-pinned.sh — third-party GitHub Actions (SUPPLY-002).
# This one covers what those two do not: the compose stacks, the demo seed
# Dockerfile, and the IaC job manifests under deploy/.
#
# Out of scope (each an explicit, documented exemption in ref_is_pinned):
#   - refs already carrying an `@sha256:` digest;
#   - build-arg / env indirection (`${BASE_IMAGE}`) — check-base-pinned.sh owns
#     those, and the release workflow resolves them to digests;
#   - Helm/Go-template refs (`{{ include "trstctl.image" . }}`);
#   - locally-built refs (`*:local`) — produced by a `build:` in the same file;
#   - `FROM <stage>` where <stage> is a stage DECLARED EARLIER in the same
#     Dockerfile, plus the reserved `scratch`.
#
# Stage names are PARSED from the `AS <name>` clauses actually present, never
# inferred from position. Positional selection (first/last FROM) is precisely how
# check-base-pinned.sh rotted once the Dockerfile grew leading and trailing
# stages, so this guard does not repeat it.
#
# Each pure function below is unit-tested by check-compose-images-pinned_selftest.sh.
set -euo pipefail

# ref_is_pinned <ref>
# True (0) iff the image reference is immutable or an out-of-scope indirection.
# False (1) iff it names a mutable tag that must be digest-pinned.
ref_is_pinned() {
	local ref="$1"
	[[ -n "$ref" ]] || return 0                # `image:` with a mapping below it, not a ref
	[[ "$ref" != *'@sha256:'* ]] || return 0   # already digest-pinned
	[[ "$ref" != *'$'* ]] || return 0          # ${BUILD_IMAGE} / $BASE_IMAGE indirection
	[[ "$ref" != *'{{'* ]] || return 0         # Helm / Go template
	[[ "$ref" != *':local' ]] || return 0      # locally built by a `build:` stanza
	return 1
}

# scan_dockerfile <file>
# Prints `<file>:<lineno>: <ref>` for every FROM that names a mutable tag. A FROM
# whose ref matches a stage declared by an EARLIER `AS <name>` in the same file
# (or the reserved `scratch`) is an intra-file reference, not a registry pull.
scan_dockerfile() {
	local df="$1" lineno=0 line ref stage stages=" scratch "
	while IFS= read -r line || [[ -n "$line" ]]; do
		lineno=$((lineno + 1))
		[[ "$line" =~ ^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+ ]] || continue
		# Drop the FROM keyword, any `--platform=` flags, and a trailing comment.
		ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+//; s/--[a-zA-Z-]+=[^[:space:]]+[[:space:]]+//g; s/[[:space:]]*#.*$//')"
		stage="$(printf '%s' "$ref" | sed -nE 's/.*[[:space:]][Aa][Ss][[:space:]]+([^[:space:]]+).*/\1/p')"
		ref="${ref%%[[:space:]]*}"
		if [[ "$stages" != *" $ref "* ]] && ! ref_is_pinned "$ref"; then
			printf '%s:%s: %s\n' "$df" "$lineno" "$ref"
		fi
		[[ -z "$stage" ]] || stages+="$stage "
	done <"$df"
}

# scan_manifest <file>
# Prints `<file>:<lineno>: <ref>` for every `image:` value naming a mutable tag.
# `image:` is matched both as a plain mapping key and as the first key of a YAML
# sequence item (`- image: ...`), which is equally legal in a pod spec.
scan_manifest() {
	local mf="$1" lineno=0 line ref
	while IFS= read -r line || [[ -n "$line" ]]; do
		lineno=$((lineno + 1))
		[[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?image:([[:space:]]|$) ]] || continue
		ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*(-[[:space:]]+)?image:[[:space:]]*//; s/[[:space:]]*#.*$//; s/[[:space:]]+$//; s/^["'\'']//; s/["'\'']$//')"
		ref_is_pinned "$ref" || printf '%s:%s: %s\n' "$mf" "$lineno" "$ref"
	done <"$mf"
}

# deploy_files <root>
# Prints every deploy/ file this guard inspects, sorted, Dockerfiles first.
deploy_files() {
	local root="$1"
	{
		find "${root}/deploy" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \) 2>/dev/null | sort
		find "${root}/deploy" -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.tpl' \) 2>/dev/null | sort
	}
}

main() {
	local root="${1:-.}"
	local offenders="" checked=0 f out

	if [[ ! -d "${root}/deploy" ]]; then
		echo "FAIL: no deploy directory at ${root}/deploy"
		return 1
	fi

	while IFS= read -r f; do
		[[ -n "$f" ]] || continue
		checked=$((checked + 1))
		case "$(basename "$f")" in
		Dockerfile | Dockerfile.* | *.Dockerfile) out="$(scan_dockerfile "$f")" ;;
		*) out="$(scan_manifest "$f")" ;;
		esac
		[[ -z "$out" ]] || offenders+="$out"$'\n'
	done < <(deploy_files "$root")

	if [[ "$checked" -eq 0 ]]; then
		echo "FAIL: found no Dockerfiles or YAML manifests under ${root}/deploy to check"
		return 1
	fi

	if [[ -n "${offenders//[$'\n' ]/}" ]]; then
		echo "FAIL: deploy/ references container images by a mutable tag, not an @sha256 digest (SUPPLY-008):"
		printf '%s' "$offenders" | sed '/^$/d; s/^/        /'
		echo
		echo "Resolve each ref to its digest and pin it, keeping the tag for humans:"
		echo "    docker buildx imagetools inspect <name>:<tag> --format '{{.Manifest.Digest}}'"
		echo "    image: <name>:<tag>@sha256:<digest>"
		echo "Keep Dependabot (docker ecosystem, one entry per deploy/ directory) to bump the digest pins."
		return 1
	fi

	echo "ok:   every third-party image under ${root}/deploy is @sha256 digest-pinned (${checked} files checked)"
	return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
