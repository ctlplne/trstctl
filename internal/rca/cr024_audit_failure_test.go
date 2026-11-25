// SPDX-License-Identifier: BUSL-1.1

package rca

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestCR024GatherWithholdsEvidenceWhenAuditFails(t *testing.T) {
	appendErr := errors.New("injected evidence audit append failure")
	q := scopedQuery{byTenant: map[string][]Record{
		"tenant-a": {{Source: "audit", ID: "event-1", Summary: "renewal failed"}},
	}}
	p := NewPipeline(q, auditsink.AuditorFunc(func(context.Context, string, string, []byte) error { return appendErr }))
	ev, err := p.Gather(t.Context(), "tenant-a", "cert-1", "why did renewal fail")
	if !errors.Is(err, appendErr) || len(ev.Items) != 0 {
		t.Fatalf("evidence escaped without its read audit: items=%d err=%v", len(ev.Items), err)
	}
}
