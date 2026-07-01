#!/usr/bin/env bash
# coverage-normalize.sh - collapse duplicate source blocks in a merged Go
# -coverpkg profile.
#
# Go writes one row per covered source block per test binary when a broad
# -coverpkg set is used. For a repo-wide coverage gate, the meaningful unit is
# the unique source block: count its statements once, and treat it as covered if
# any duplicate row has a non-zero execution count.
set -euo pipefail

usage() {
	echo "usage: scripts/ci/coverage-normalize.sh <input-profile|-> <output-profile>" >&2
}

if [[ $# -ne 2 ]]; then
	usage
	exit 2
fi

input="$1"
output="$2"
if [[ -z "$output" || "$output" == "-" ]]; then
	echo "coverage-normalize: output profile must be a file path" >&2
	exit 2
fi

source_path="$input"
if [[ "$input" == "-" ]]; then
	source_path="/dev/stdin"
elif [[ ! -f "$input" ]]; then
	echo "coverage-normalize: input profile '$input' not found" >&2
	exit 2
fi
MODULE="${MODULE:-trstctl.com/trstctl}"

tmp="$(mktemp "${output}.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

awk -v module="$MODULE" '
	function trim(s) {
		gsub(/^[[:space:]]+/, "", s)
		gsub(/[[:space:]]+$/, "", s)
		return s
	}
	function is_orphan_fragment(s,    fragment) {
		fragment = trim(s)
		return fragment == "" || index(module, fragment) == 1
	}
	function add_row(row, line_no,    fields, block, stmts, count) {
		split(row, fields, " ")
		block = fields[1]
		stmts = fields[2]
		count = fields[3] + 0
		if (!(block in seen)) {
			seen[block] = 1
			order[++norder] = block
			block_stmts[block] = stmts
			block_count[block] = count
			return
		}
		if (block_stmts[block] != stmts) {
			printf("coverage-normalize: duplicate block %s has inconsistent statement counts (%s vs %s)\n", block, block_stmts[block], stmts) > "/dev/stderr"
			exit 1
		}
		if (count > block_count[block]) block_count[block] = count
	}
	NR == 1 {
		if ($1 != "mode:" || NF != 2) {
			printf("coverage-normalize: malformed cover mode header: %s\n", $0) > "/dev/stderr"
			exit 1
		}
		module_re = module
		gsub(/[.]/, "[.]", module_re)
		row_re = module_re "/[^[:space:]]+[.]go:[0-9]+[.][0-9]+,[0-9]+[.][0-9]+ [0-9]+ [0-9]+"
		mode = $0
		next
	}
	{
		line = $0
		matched = 0
		residue = 0
		while (match(line, row_re)) {
			before = substr(line, 1, RSTART - 1)
			if (before ~ /[^[:space:]]/) residue = 1
			row = substr(line, RSTART, RLENGTH)
			add_row(row, NR)
			matched = 1
			line = substr(line, RSTART + RLENGTH)
		}
		if (!matched) {
			if (is_orphan_fragment(line)) {
				malformed_fragments++
				next
			}
			printf("coverage-normalize: malformed cover row at line %d: %s\n", NR, $0) > "/dev/stderr"
			exit 1
		}
		if (line ~ /[^[:space:]]/) residue = 1
		if (residue) malformed_fragments++
	}
	END {
		if (mode == "") {
			print "coverage-normalize: missing cover mode header" > "/dev/stderr"
			exit 1
		}
		if (malformed_fragments > 0) {
			printf("coverage-normalize: ignored malformed fragments on %d coverprofile line(s)\n", malformed_fragments) > "/dev/stderr"
		}
		print mode
		for (i = 1; i <= norder; i++) {
			block = order[i]
			printf "%s %s %s\n", block, block_stmts[block], block_count[block]
		}
	}
' "$source_path" >"$tmp"

mv "$tmp" "$output"
trap - EXIT
