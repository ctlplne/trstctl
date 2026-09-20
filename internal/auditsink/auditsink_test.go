// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"context"
	"testing"
)

func TestRecorderCountsAndCopies(t *testing.T) {
	r := &Recorder{}
	ctx := context.Background()
	_ = r.Audit(ctx, "a", "t1", []byte("x"))
	_ = r.Audit(ctx, "a", "t1", []byte("y"))
	_ = r.Audit(ctx, "b", "t1", nil)
	if r.Count("a") != 2 || r.Count("b") != 1 || r.Count("missing") != 0 {
		t.Errorf("counts wrong: a=%d b=%d missing=%d", r.Count("a"), r.Count("b"), r.Count("missing"))
	}
	if len(r.Records()) != 3 {
		t.Fatalf("records = %d, want 3", len(r.Records()))
	}
	// The recorder must copy the payload so a caller mutating its buffer afterward
	// cannot retroactively change a recorded event.
	buf := []byte("z")
	_ = r.Audit(ctx, "d", "t1", buf)
	buf[0] = 'Q'
	for _, rec := range r.Records() {
		if rec.Type == "d" && string(rec.Data) != "z" {
			t.Errorf("recorded data not copied: %q", rec.Data)
		}
	}
}

func TestNopDiscards(t *testing.T) {
	if err := (Nop{}).Audit(context.Background(), "a", "t1", []byte("x")); err != nil {
		t.Errorf("Nop.Audit returned %v, want nil", err)
	}
}
