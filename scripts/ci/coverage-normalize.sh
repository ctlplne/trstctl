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
		return fragment == "" || index(module, fragment) == 1 || index(fragment, module) == 1 || fragment ~ /^[0-9]+([[:space:]]+[0-9]+)?([[:space:]]+[0-9]+)?$/
	}
	function is_source_suffix_fragment(s,    fields, block) {
		s = trim(s)
		if (split(s, fields, " ") != 3) return 0
		block = fields[1]
		return block ~ /^[^[:space:]]+[.]go:[0-9]+[.][0-9]+,[0-9]+[.][0-9]+$/ && fields[2] ~ /^[0-9]+$/ && fields[3] ~ /^[0-9]+$/
	}
	function remember_source_suffix(s, line_no,    fields) {
		s = trim(s)
		split(s, fields, " ")
		pending_block[++npending] = fields[1]
		pending_stmts[npending] = fields[2]
		pending_count[npending] = fields[3] + 0
		pending_line[npending] = line_no
		pending_raw[npending] = s
	}
	function add_row(row, line_no,    fields, block, stmts, count, tail, nested) {
		split(row, fields, " ")
		block = fields[1]
		stmts = fields[2]
		count = fields[3] + 0
		# A very large multi-package profile can contain a source path fused to
		# the front of the next complete module path. Keep the complete suffix;
		# its coordinates and counters are intact, while the prefix is not a
		# source file that can exist in this module.
		tail = substr(block, length(module) + 2)
		nested = index(tail, module "/")
		if (nested > 0) {
			block = substr(tail, nested)
			malformed_fragments++
		}
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
			# Go has occasionally emitted the tail of one otherwise duplicated
			# source row when a very large -coverpkg profile is assembled. Do not
			# guess its path here. Defer it until END, then accept it only when its
			# complete path+coordinates suffix identifies exactly one valid row.
			if (is_source_suffix_fragment(line)) {
				remember_source_suffix(line, NR)
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
		for (p = 1; p <= npending; p++) {
			matches = 0
			resolved = ""
			for (i = 1; i <= norder; i++) {
				candidate = order[i]
				if (length(candidate) >= length(pending_block[p]) && substr(candidate, length(candidate) - length(pending_block[p]) + 1) == pending_block[p]) {
					matches++
					resolved = candidate
				}
			}
			if (matches != 1) {
				printf("coverage-normalize: malformed cover row at line %d: %s (suffix matched %d complete rows)\n", pending_line[p], pending_raw[p], matches) > "/dev/stderr"
				exit 1
			}
			if (block_stmts[resolved] != pending_stmts[p]) {
				printf("coverage-normalize: recovered suffix %s has inconsistent statement counts (%s vs %s)\n", pending_block[p], block_stmts[resolved], pending_stmts[p]) > "/dev/stderr"
				exit 1
			}
			if (pending_count[p] > block_count[resolved]) block_count[resolved] = pending_count[p]
			malformed_fragments++
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
