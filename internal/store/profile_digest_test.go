// SPDX-License-Identifier: MPL-2.0

package store

import (
	"encoding/json"
	"testing"
)

func TestProfileSpecDigestIsStableAcrossJSONObjectOrdering(t *testing.T) {
	left := json.RawMessage(`{"allowed_protocols":["api","acme"],"max_validity":"24h","limits":{"count":10,"enabled":true}}`)
	right := json.RawMessage(`{ "limits": { "enabled": true, "count": 10 }, "max_validity": "24h", "allowed_protocols": ["api", "acme"] }`)

	if got, want := ProfileSpecDigest(left), ProfileSpecDigest(right); got != want {
		t.Fatalf("semantic profile digests differ: %s != %s", got, want)
	}
}

func TestProfileSpecDigestStillHandlesInvalidImportedBytesDeterministically(t *testing.T) {
	spec := json.RawMessage(`{"broken":`)
	first := ProfileSpecDigest(spec)
	second := ProfileSpecDigest(spec)
	if first == "sha256:" || first != second {
		t.Fatalf("invalid imported spec digest = (%q, %q), want stable non-empty digest", first, second)
	}
}
