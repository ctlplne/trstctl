package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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
// raw file, so an equal hash is the only thing that proves "the SDK was built
// from exactly this contract". A whitespace-only reformat still counts as drift
// and must be re-copied, which keeps the two files trivially diffable.
func TestSDKSpecPinnedToGolden(t *testing.T) {
	golden := readSpecFile(t, filepath.Join("testdata", "openapi.golden.json"))
	// The repository layout is fixed (internal/api -> ../../clients/sdk); if it
	// ever moves, this test should fail loudly rather than silently skip.
	pinned := readSpecFile(t, filepath.Join("..", "..", "clients", "sdk", "openapi.json"))

	if !bytes.Equal(golden, pinned) {
		t.Fatalf("clients/sdk/openapi.json has drifted from the served OpenAPI golden.\n"+
			"  golden sha256 = %s (%d bytes)\n"+
			"  pinned sha256 = %s (%d bytes)\n"+
			"The published SDKs are generated from clients/sdk/openapi.json; it must equal "+
			"the served spec or generated clients desync from the API (PRODUCT-007).\n"+
			"Re-pin with: cp internal/api/testdata/openapi.golden.json clients/sdk/openapi.json && make sdk",
			sha(golden), len(golden), sha(pinned), len(pinned))
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

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
