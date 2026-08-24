#!/usr/bin/env bash
# Self-test for coverage-normalize.sh. A merged -coverpkg profile repeats the
# same source block once per test binary; the normalizer must count that source
# block once and mark it covered if any duplicate execution count is non-zero.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
normalizer="${here}/coverage-normalize.sh"

fails=0
check() { # check <desc> <expected> <actual>
	if [[ "$2" == "$3" ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (expected $2, got $3)"
		fails=1
	fi
}

duplicate_profile="$(mktemp)"
normalized_profile="$(mktemp)"
bad_profile="$(mktemp)"
bad_out="$(mktemp)"
repaired_profile="$(mktemp)"
repaired_out="$(mktemp)"
orphan_profile="$(mktemp)"
orphan_out="$(mktemp)"
numeric_orphan_profile="$(mktemp)"
numeric_orphan_out="$(mktemp)"
path_orphan_profile="$(mktemp)"
path_orphan_out="$(mktemp)"
trap 'rm -f "$duplicate_profile" "$normalized_profile" "$bad_profile" "$bad_out" "$repaired_profile" "$repaired_out" "$orphan_profile" "$orphan_out" "$numeric_orphan_profile" "$numeric_orphan_out" "$path_orphan_profile" "$path_orphan_out"' EXIT
covered_block="trstctl.com/trstctl/cmd/terraform-provider-trstctl/main.go:13.13,17.16"
uncovered_block="trstctl.com/trstctl/cmd/trstctl/connector.go:39.2,40.16"
if [[ -z "${GOCACHE:-}" ]]; then
	export GOCACHE="${TMPDIR:-/tmp}/trstctl-cover-normalize-selftest-gocache"
	mkdir -p "$GOCACHE"
fi

cat >"$duplicate_profile" <<EOF
mode: atomic
${covered_block} 2 0
${covered_block} 2 3
${uncovered_block} 2 0
${covered_block} trst${uncovered_block} 2 0
EOF

"$normalizer" "$duplicate_profile" "$normalized_profile"

expected="$(mktemp)"
trap 'rm -f "$duplicate_profile" "$normalized_profile" "$bad_profile" "$bad_out" "$repaired_profile" "$repaired_out" "$orphan_profile" "$orphan_out" "$numeric_orphan_profile" "$numeric_orphan_out" "$path_orphan_profile" "$path_orphan_out" "$expected"' EXIT
cat >"$expected" <<EOF
mode: atomic
${covered_block} 2 3
${uncovered_block} 2 0
EOF

if cmp -s "$expected" "$normalized_profile"; then
	echo "PASS: duplicate source blocks collapse to one covered row"
else
	echo "FAIL: normalized profile did not match expected output"
	diff -u "$expected" "$normalized_profile" || true
	fails=1
fi

total="$(go tool cover -func="$normalized_profile" | awk '/^total:/ {print $3}')"
check "normalized profile reports true source coverage" "50.0%" "$total"

cat >"$repaired_profile" <<EOF
mode: atomic
${covered_block} trst${uncovered_block} 2 0
${covered_block} 2 3
EOF

"$normalizer" "$repaired_profile" "$repaired_out"
if go tool cover -func="$repaired_out" >/dev/null; then
	echo "PASS: repairs a fused cover row with an orphaned truncated prefix"
else
	echo "FAIL: repaired profile is not accepted by go tool cover"
	fails=1
fi

cat >"$repaired_profile" <<EOF
mode: atomic
trstctl.com/trstctl/internal/${covered_block} 2 0
${covered_block} 2 3
EOF

"$normalizer" "$repaired_profile" "$repaired_out"
if go tool cover -func="$repaired_out" >/dev/null \
	&& grep -qx "${covered_block} 2 3" "$repaired_out" \
	&& ! grep -q 'internal/trstctl.com/trstctl/' "$repaired_out"; then
	echo "PASS: repairs a source-path prefix fused to a complete module row"
else
	echo "FAIL: fused source-path repair did not preserve the complete valid row"
	fails=1
fi

cat >"$orphan_profile" <<EOF
mode: atomic
trstc
${covered_block} 2 3
EOF

"$normalizer" "$orphan_profile" "$orphan_out"
if go tool cover -func="$orphan_out" >/dev/null; then
	echo "PASS: ignores an orphan-only truncated coverage prefix"
else
	echo "FAIL: orphan-only fragment repair is not accepted by go tool cover"
	fails=1
fi

cat >"$numeric_orphan_profile" <<EOF
mode: atomic
${covered_block} 2 3
94 2 0
EOF

"$normalizer" "$numeric_orphan_profile" "$numeric_orphan_out"
if go tool cover -func="$numeric_orphan_out" >/dev/null; then
	echo "PASS: ignores a standalone numeric-only truncated row suffix"
else
	echo "FAIL: numeric-only row-suffix repair is not accepted by go tool cover"
	fails=1
fi

cat >"$path_orphan_profile" <<EOF
mode: atomic
${covered_block} 2 3
trstctl.com/trstctl/inte
EOF

"$normalizer" "$path_orphan_profile" "$path_orphan_out"
if go tool cover -func="$path_orphan_out" >/dev/null; then
	echo "PASS: ignores a standalone truncated module-path coverage fragment"
else
	echo "FAIL: module-path orphan fragment repair is not accepted by go tool cover"
	fails=1
fi

cat >"$bad_profile" <<EOF
mode: atomic
${covered_block} 2 1
${covered_block} 3 1
EOF

set +e
"$normalizer" "$bad_profile" "$bad_out" >/dev/null 2>&1
bad_status=$?
set -e
check "rejects duplicate blocks with inconsistent statement counts" "1" "$bad_status"

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
