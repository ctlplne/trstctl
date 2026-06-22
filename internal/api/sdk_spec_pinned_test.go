package api

import (
	"bytes"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestSDKSpecPinnedToGolden is the PRODUCT-007 anti-drift guard: the OpenAPI
// document the published client SDKs are generated from
// (clients/sdk/openapi.json) MUST be byte-identical to the served golden spec
// (internal/api/testdata/openapi.golden.json), which TestOpenAPIGolden in turn
// pins to the live ServeMux. Chained together, this means a generated SDK can
// never silently desync from the API: if the backend adds, renames, or removes
// a field, the golden changes, this test goes red, and the SDK copy + generated
// clients must be regenerated (`make sdk`) before the change can ship.
//
// We compare bytes (not parsed JSON) on purpose: the SDK generators consume the
// raw file, so byte equality is the only thing that proves "the SDK was built
// from exactly this contract". A whitespace-only reformat still counts as drift
// and must be re-copied, which keeps the two files trivially diffable. The
// fingerprint in the failure message is a non-cryptographic FNV digest used only
// for at-a-glance diffing — no crypto/* import is taken here, so the AN-3
// boundary (all real cryptography lives in internal/crypto) is preserved.
func TestSDKSpecPinnedToGolden(t *testing.T) {
	golden := readSpecFile(t, filepath.Join("testdata", "openapi.golden.json"))
	// The repository layout is fixed (internal/api -> ../../clients/sdk); if it
	// ever moves, this test should fail loudly rather than silently skip.
	pinned := readSpecFile(t, filepath.Join("..", "..", "clients", "sdk", "openapi.json"))

	if !bytes.Equal(golden, pinned) {
		t.Fatalf("clients/sdk/openapi.json has drifted from the served OpenAPI golden.\n"+
			"  golden fnv = %s (%d bytes)\n"+
			"  pinned fnv = %s (%d bytes)\n"+
			"The published SDKs are generated from clients/sdk/openapi.json; it must equal "+
			"the served spec or generated clients desync from the API (PRODUCT-007).\n"+
			"Re-pin with: cp internal/api/testdata/openapi.golden.json clients/sdk/openapi.json && make sdk",
			fingerprint(golden), len(golden), fingerprint(pinned), len(pinned))
	}
}

func readSpecFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// fingerprint is a non-cryptographic content digest for diff-at-a-glance test
// diagnostics only (FNV-1a). It must not be used for any security decision.
func fingerprint(b []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return strconv.FormatUint(h.Sum64(), 16)
}
