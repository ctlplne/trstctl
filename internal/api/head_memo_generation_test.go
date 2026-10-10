// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"testing"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestHeadMemoRejectsSameHeadFromAnotherHistoryGeneration(t *testing.T) {
	log, err := events.Open(t.Context(), configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(t.Context(), events.Event{Type: "test.memo", TenantID: "tenant-a", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	stream, generation, err := log.ActiveHistoryIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var memo headMemo[int]
	memo.prime("tenant-a\x00"+stream+"\x00other-generation", 99, head)
	builds := 0
	rebuild := func(context.Context) (int, uint64, error) {
		builds++
		return 1, head, nil
	}
	got, err := memo.get(t.Context(), log, "tenant-a", rebuild, nil)
	if err != nil || got != 1 || builds != 1 {
		t.Fatalf("same-head foreign generation memo = %d builds=%d err=%v", got, builds, err)
	}
	if cached := memo.byTenant["tenant-a\x00"+stream+"\x00"+generation]; cached.value != 1 || cached.atSeq != head {
		t.Fatalf("live generation cache entry = %+v", cached)
	}
	got, err = memo.get(t.Context(), log, "tenant-a", rebuild, nil)
	if err != nil || got != 1 || builds != 1 {
		t.Fatalf("same-generation head memo = %d builds=%d err=%v", got, builds, err)
	}
}
