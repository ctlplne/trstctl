#!/usr/bin/env bash
# ClusterFuzzLite / OSS-Fuzz build script for trstctl's Go native fuzz targets
# (FUZZ-003). It discovers every `func FuzzXxx(f *testing.F)` under ./internal and ./ee and
# compiles it into a libFuzzer binary via the base image's native-Go helper, so
# the OSS-Fuzz-family runner can fuzz each one continuously and accumulate a corpus.
#
# Discovery is automatic so a newly-added FuzzXxx is fuzzed without editing this
# file; the in-repo TestEveryUntrustedParserIsFuzzed guard ensures every untrusted
# parser HAS a target, and this script ensures each target is actually built.
set -euo pipefail

cd "${SRC}/trstctl"

# Production images build the real Vite bundle before compiling Go. The fuzz
# image intentionally does not ship or execute a browser, but some Enterprise
# parser dependency graphs still reach internal/webui's go:embed declaration.
# Give the compiler one explicit non-production file so it can type-check that
# graph; the release gate still requires the real Vite bundle and this marker is
# removed when the build script exits.
webui_fuzz_placeholder=""
if [[ ! -e internal/webui/dist/index.html ]]; then
	mkdir -p internal/webui/dist
	webui_fuzz_placeholder="internal/webui/dist/index.html"
	printf '%s\n' '<!doctype html><title>ClusterFuzz compile-only placeholder</title>' >"${webui_fuzz_placeholder}"
fi

# The upstream helper temporarily rewrites every *_test.go file in a target
# directory into the production package. If that directory also contains an
# external `package foo_test`, the rewritten directory has two package names and
# Go rejects it before the fuzzer links. External-package fuzz entrypoints live in
# the isolated clusterfuzz bridge packages (locked by the docs guard below), so
# park the remaining external black-box tests while this disposable builder runs.
# Restore them on exit as a safety belt for developers invoking this script in a
# reusable checkout instead of the normal throw-away CI container.
external_test_hold="$(mktemp -d)"
external_test_manifest="${external_test_hold}/manifest"
fuzz_target_manifest="${external_test_hold}/fuzz-targets"
: >"${external_test_manifest}"
: >"${fuzz_target_manifest}"

restore_external_tests() {
	while IFS= read -r -d '' file; do
		source_file="${external_test_hold}/${file#./}"
		mkdir -p "$(dirname "${file}")"
		mv "${source_file}" "${file}"
	done <"${external_test_manifest}"
	if [[ -n "${webui_fuzz_placeholder}" ]]; then
		rm -f "${webui_fuzz_placeholder}"
		rmdir internal/webui/dist 2>/dev/null || true
	fi
}
trap restore_external_tests EXIT

while IFS= read -r -d '' file; do
	package_name="$(awk '$1 == "package" { print $2; exit }' "${file}")"
	if [[ "${package_name}" == *_test ]]; then
		destination="${external_test_hold}/${file#./}"
		mkdir -p "$(dirname "${destination}")"
		mv "${file}" "${destination}"
		printf '%s\0' "${file}" >>"${external_test_manifest}"
	fi
done < <(find ./internal ./ee -type f -name '*_test.go' -print0)

# Each line: <import-path> <FuzzName>
grep -rE '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' ./internal ./ee | while read -r line; do
	file="${line%%:func *}"
	fn="$(printf '%s\n' "$line" | sed -E 's/.*:func (Fuzz[A-Za-z0-9_]+)\(.*/\1/')"
	dir="$(dirname "$file")"
	# Native Go fuzz functions live in *_test.go. compile_go_fuzzer is the legacy
	# helper for production-package entrypoints and cannot resolve them; v2 is the
	# OSS-Fuzz helper specifically for func FuzzXxx(*testing.F).
	pkg="trstctl.com/trstctl/${dir#./}"
	# Fuzz function names are not repository-wide unique (for example several
	# packages intentionally expose FuzzDecode). Include the package path in the
	# artifact name so a later target cannot overwrite an earlier binary while
	# leaving the build deceptively green.
	target="${dir#./}_${fn}"
	target="${target//\//_}"
	target="${target//./_}"
	target="${target//-/_}"
	if grep -Fqx -- "${target}" "${fuzz_target_manifest}"; then
		echo "duplicate ClusterFuzz output name: ${target}" >&2
		exit 1
	fi
	printf '%s\n' "${target}" >>"${fuzz_target_manifest}"
	echo "compiling ${pkg} ${fn} -> ${target}"
	compile_native_go_fuzzer_v2 "${pkg}" "${fn}" "${target}"
	if [[ ! -x "${OUT}/${target}" ]]; then
		echo "ClusterFuzz helper did not produce executable ${OUT}/${target}" >&2
		exit 1
	fi
done

target_count="$(wc -l <"${fuzz_target_manifest}" | tr -d '[:space:]')"
echo "built ${target_count} unique ClusterFuzz executables"
