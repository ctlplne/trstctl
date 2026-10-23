// SPDX-License-Identifier: BUSL-1.1

package byok

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
)

// eMudhra, Part 4: an externally generated key can arrive weak. The BYOK
// on-ramp refuses it, records nothing, and an ordinary key still imports.
func TestImportSignerRefusesAWeakKey(t *testing.T) {
	ctx := context.Background()
	der, err := weakkeytest.SmallScalarPKCS8("P-384", 4)
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	if _, err := ImportSigner(ctx, sink, testTenant, "weak", crypto.ECDSAP384, der); err == nil || !strings.Contains(err.Error(), "refusing a weak key") {
		t.Fatalf("weak import: err = %v", err)
	}
	if got := sink.types(); len(got) != 0 {
		t.Fatalf("a refused import was recorded: %v", got)
	}
	ordinary, err := crypto.GeneratePKCS8(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ImportSigner(ctx, sink, testTenant, "ordinary", crypto.ECDSAP384, ordinary)
	if err != nil {
		t.Fatalf("ordinary import: %v", err)
	}
	t.Cleanup(func() { _ = m.Zeroize(ctx, testTenant) })
}
