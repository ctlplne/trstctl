// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A211: the issuers a scan kept for a leaf project per tenant: a newer
// observation replaces them, an older or replayed one changes nothing, and
// tenant B reads none of tenant A's.
func TestScannedCertificateChainsProjectPerTenant(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	leaf := strings.Repeat("a2", 32)
	at := time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC)
	apply := func(sequence uint64, issuers ...[]byte) {
		t.Helper()
		rows := make([]store.ScannedIssuer, 0, len(issuers))
		for i, der := range issuers {
			rows = append(rows, store.ScannedIssuer{Position: i + 1, CertificateDER: der, SHA256: strings.Repeat("c", 63) + string(rune('0'+i))})
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyScannedCertificateChainTx(ctx, tx, tenantA, leaf, rows, at, sequence)
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(tenant string) []store.ScannedIssuer {
		t.Helper()
		chains, err := s.ScannedCertificateChains(ctx, tenant, []string{leaf})
		if err != nil {
			t.Fatal(err)
		}
		return chains[leaf]
	}
	apply(2101, []byte("intermediate"), []byte("root"))
	if got := read(tenantA); len(got) != 2 || !bytes.Equal(got[0].CertificateDER, []byte("intermediate")) || got[1].Position != 2 {
		t.Fatalf("kept chain = %+v", got)
	}
	apply(2102, []byte("new intermediate"))
	if got := read(tenantA); len(got) != 1 || !bytes.Equal(got[0].CertificateDER, []byte("new intermediate")) {
		t.Fatalf("a newer observation did not replace the chain: %+v", got)
	}
	apply(2101, []byte("intermediate"), []byte("root"))
	if got := read(tenantA); len(got) != 1 {
		t.Fatalf("a replayed older observation changed the chain: %+v", got)
	}
	if got := read(tenantB); len(got) != 0 {
		t.Fatalf("tenant B read tenant A's chain: %+v", got)
	}
}
