// SPDX-License-Identifier: BUSL-1.1

package audit_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/audit"
)

// An unbroken run of a tenant's records selected without a content filter — a
// latest window, an as-of point, a limit, a cursor — keeps the hashes those
// records have in the tenant's full chain, seeded from the head just before its
// first record, so an anchor over the full chain can be re-checked inside it.
// A content-filtered selection stays a chain of its own from the archived
// prefix, even when it happens to match consecutive records. ChainHead follows
// the full chain without holding it and matches the last hash of an unfiltered
// export.
func TestUnbrokenWindowsKeepFullChainHashes(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	for _, typ := range []string{"x.one", "x.two", "x.two", "x.one", "x.two", "x.one"} {
		appendEvent(t, log, tenantA, typ)
		appendEvent(t, log, tenantB, typ)
	}
	svc := newService(t, log)
	full, err := svc.Search(ctx, audit.Query{TenantID: tenantA})
	if err != nil || len(full) != 6 {
		t.Fatalf("full chain = %d records, %v", len(full), err)
	}
	headAt := func(sequence uint64) string {
		if sequence == 0 {
			return ""
		}
		return full[sequence-1].Hash
	}
	for name, q := range map[string]audit.Query{
		"latest window":   {TenantID: tenantA, Limit: 2, Latest: true},
		"as-of point":     {TenantID: tenantA, AsOfSequence: 4},
		"earliest window": {TenantID: tenantA, Limit: 3},
		"after cursor":    {TenantID: tenantA, AfterSequence: 3},
	} {
		records, seed, err := svc.SearchWithSeed(ctx, q)
		if err != nil || !audit.FullChain(q, records) {
			t.Fatalf("%s: %d records, full chain=%t, %v", name, len(records), audit.FullChain(q, records), err)
		}
		if want := headAt(records[0].Sequence - 1); seed != want {
			t.Fatalf("%s: seed = %q, want the full chain's head at %d (%q)", name, seed, records[0].Sequence-1, want)
		}
		for _, record := range records {
			if record.Hash != full[record.Sequence-1].Hash {
				t.Fatalf("%s: record %d hash differs from the full chain", name, record.Sequence)
			}
		}
		if _, err := audit.VerifyChainFrom(seed, records); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	for name, q := range map[string]audit.Query{
		"content filter with gaps":      {TenantID: tenantA, Types: []string{"x.one"}},
		"content filter matching a run": {TenantID: tenantA, Types: []string{"x.two"}, AfterSequence: 1, AsOfSequence: 3},
		"one matching record":           {TenantID: tenantA, Types: []string{"x.two"}, Limit: 1, Latest: true},
	} {
		records, seed, err := svc.SearchWithSeed(ctx, q)
		if err != nil || len(records) == 0 || audit.FullChain(q, records) || seed != "" {
			t.Fatalf("%s: %d records, seed %q, %v", name, len(records), seed, err)
		}
		if _, err := audit.VerifyChainFrom("", records); err != nil {
			t.Fatalf("%s must be a chain of its own from the archived prefix: %v", name, err)
		}
		if records[0].Sequence > 1 && records[0].Hash == full[records[0].Sequence-1].Hash {
			t.Fatalf("%s carried the full chain's hash", name)
		}
	}

	position, err := svc.ChainHead(ctx, tenantA)
	if err != nil || position.Sequence != 6 || position.Head != full[5].Hash || !position.Time.Equal(full[5].Time) {
		t.Fatalf("ChainHead = %+v, %v; want sequence 6 head %s", position, err, full[5].Hash)
	}
	if empty, err := svc.ChainHead(ctx, "33333333-3333-3333-3333-333333333333"); err != nil || empty.Sequence != 0 || empty.Head != "" {
		t.Fatalf("empty tenant ChainHead = %+v, %v", empty, err)
	}
	if _, err := svc.ChainHead(ctx, ""); err == nil {
		t.Fatal("ChainHead without a tenant must fail closed")
	}
}

// After retention archives a prefix, windows and ChainHead continue from the
// checkpoint's boundary hash exactly as the full chain did.
func TestChainHeadContinuesFromTheArchivedPrefix(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	var streamSeqs []uint64
	for i := 0; i < 5; i++ {
		streamSeqs = append(streamSeqs, appendEvent(t, log, tenantA, "x.step"))
	}
	plain := newService(t, log)
	full, err := plain.Search(ctx, audit.Query{TenantID: tenantA})
	if err != nil || len(full) != 5 {
		t.Fatal(err)
	}
	checkpoints := &memCheckpoints{}
	if err := checkpoints.SaveAuditCheckpoint(ctx, audit.Checkpoint{
		TenantID: tenantA, BoundarySeq: streamSeqs[1], BoundaryHash: full[1].Hash, RecordCount: 2, ArchiveURI: "file:///archive/1",
	}); err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, nil, audit.WithCheckpoints(checkpoints))
	position, err := svc.ChainHead(ctx, tenantA)
	if err != nil || position.Sequence != 5 || position.Head != full[4].Hash {
		t.Fatalf("ChainHead after an archived prefix = %+v, %v", position, err)
	}
	window, seed, err := svc.SearchWithSeed(ctx, audit.Query{TenantID: tenantA, Limit: 1, Latest: true})
	if err != nil || len(window) != 1 || seed != full[3].Hash || window[0].Hash != full[4].Hash {
		t.Fatalf("latest window after an archived prefix = %+v, seed %q, %v", window, seed, err)
	}
}
