#!/usr/bin/env bash
# ClusterFuzzLite / OSS-Fuzz build script for trstctl's Go native fuzz targets
# (FUZZ-003). It discovers every `func FuzzXxx(f *testing.F)` under ./internal and ./ee and
# compiles it into a libFuzzer binary via the base image's compile_go_fuzzer, so
# the OSS-Fuzz-family runner can fuzz each one continuously and accumulate a corpus.
#
# Discovery is automatic so a newly-added FuzzXxx is fuzzed without editing this
# file; the in-repo TestEveryUntrustedParserIsFuzzed guard ensures every untrusted
# parser HAS a target, and this script ensures each target is actually built.
set -euo pipefail

cd "${SRC}/trstctl"

# Each line: <import-path> <FuzzName>
grep -rE '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' ./internal ./ee | while read -r line; do
	file="${line%%:func *}"
	fn="$(printf '%s\n' "$line" | sed -E 's/.*:func (Fuzz[A-Za-z0-9_]+)\(.*/\1/')"
	dir="$(dirname "$file")"
	# Module-qualified import path for compile_go_fuzzer.
	pkg="trstctl.com/trstctl/${dir#./}"
	echo "compiling ${pkg} ${fn}"
	compile_go_fuzzer "${pkg}" "${fn}" "${fn}"
done
