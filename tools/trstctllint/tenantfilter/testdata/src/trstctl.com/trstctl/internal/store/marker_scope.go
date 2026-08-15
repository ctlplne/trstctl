// SPDX-License-Identifier: MPL-2.0

package store

// This file pins the SCOPE of the //trstctl:system-query marker.
//
// The exemption set used to be keyed on the line number ALONE, so a marker
// anywhere in the package exempted that line number in EVERY file. An unrelated
// query silently inherited an exemption written for something else, and lost it
// again the moment either file's line numbers shifted — an AN-1 escape hatch
// whose effect depends on unrelated edits is worse than no escape hatch, because
// the analyzer's verdict stops being a property of the code it is judging.
//
// queries.go carries markers on lines 132 and 141, which exempted 132-133 and
// 141-142. The query below is deliberately placed on line 133 of THIS file and
// carries no marker of its own, so it must still be reported.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
// padding: keeps the statement below on line 133.
func unmarkedQueryAtAMarkedLineNumber() string {
	return "DELETE FROM agent_bootstrap_tokens WHERE token_hash = $1" // want "does not filter on tenant_id"
}
