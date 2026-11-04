// SPDX-License-Identifier: BUSL-1.1

package editionledger

import (
	"strings"
	"testing"
)

func TestReplaceBlocksRewritesOnlyMarkedBlocksAndFailsClosed(t *testing.T) {
	page := "before\n<!-- edition-ledger:begin a -->\nstale\n<!-- edition-ledger:end a -->\nafter\n"
	got, err := ReplaceBlocks([]byte(page), map[string]string{"a": "fresh"})
	if err != nil || string(got) != "before\n<!-- edition-ledger:begin a -->\nfresh\n<!-- edition-ledger:end a -->\nafter\n" {
		t.Fatalf("replace = %q, %v", got, err)
	}
	if _, err := ReplaceBlocks([]byte("<!-- edition-ledger:begin b -->\nx\n<!-- edition-ledger:end b -->"), map[string]string{"a": "x"}); err == nil {
		t.Fatal("an unknown block was accepted")
	}
	if _, err := ReplaceBlocks([]byte("<!-- edition-ledger:begin a -->\nx\n"), map[string]string{"a": "x"}); err == nil {
		t.Fatal("an unterminated block was accepted")
	}
}

func TestLedgerProviderCarriesEveryEnterpriseFeature(t *testing.T) {
	l, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	ent, prov := l.edition("enterprise"), l.edition("provider")
	if len(ent.Features) == 0 || len(prov.Features) <= len(ent.Features) {
		t.Fatalf("enterprise %v, provider %v", ent.Features, prov.Features)
	}
	for i, f := range ent.Features {
		if prov.Features[i] != f {
			t.Fatalf("provider does not begin with enterprise's features: %v vs %v", prov.Features, ent.Features)
		}
	}
	if len(prov.Rights) != 3 || prov.Rights[0] != "self-host" || !strings.Contains(l.Markdown(), "never a runtime license gate") {
		t.Fatalf("provider rights %v", prov.Rights)
	}
}
