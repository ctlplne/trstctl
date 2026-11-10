// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

// A36 heal: a slot is released only when the control plane says its job has
// ended and its key was never signed. An open job's slot, the current job's
// own slot and a signed key keep the first-writer fence; a released target
// takes the next job's key.
func TestReleaseEndedHostRenewPendingWipesOnlyAnEndedJobsUnsignedKey(t *testing.T) {
	state, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "rollback"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	binding := func(job int64) string { return crypto.SHA256Hex([]byte(strconv.FormatInt(job, 10))) }
	csr, key := []byte("csr-der"), []byte("-----BEGIN PRIVATE KEY-----\nunsigned\n-----END PRIVATE KEY-----\n")
	if err := state.RecordHostRenewKey("nginx", "target-a", 6, binding(6), csr, key); err != nil {
		t.Fatal(err)
	}
	// Another job is refused while job 6 holds the slot.
	if err := state.RecordHostRenewKey("nginx", "target-a", 11, binding(11), csr, key); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("a second job took a held slot: %v", err)
	}
	// Jobs ended only through 5: job 6 is still open.
	if released, err := state.ReleaseEndedHostRenewPending("nginx", "target-a", 5, 11); err != nil || released {
		t.Fatalf("an open job's key was released: %v %v", released, err)
	}
	// Job 6 resuming is never told to drop its own key.
	if released, err := state.ReleaseEndedHostRenewPending("nginx", "target-a", 9, 6); err != nil || released {
		t.Fatalf("the current job's own key was released: %v %v", released, err)
	}
	// Ended through 9 (6 and the jobs it refused, 7 to 9): job 6's key goes,
	// though it is not the newest ended job.
	if released, err := state.ReleaseEndedHostRenewPending("nginx", "target-a", 9, 11); err != nil || !released {
		t.Fatalf("job 6's unsigned key was not released: %v %v", released, err)
	}
	if p, err := state.LoadHostRenewPending("nginx", "target-a", 6, binding(6)); err != nil || p != nil {
		t.Fatalf("the released key is still readable: %v", err)
	}
	if err := state.RecordHostRenewKey("nginx", "target-a", 11, binding(11), csr, key); err != nil {
		t.Fatalf("the next job could not take the released slot: %v", err)
	}
	// A signed key stays: its certificate exists, and the rollback path owns it.
	if err := state.RecordHostRenewCertificate("nginx", "target-a", 11, binding(11), []byte("cert"), nil, "fp-11"); err != nil {
		t.Fatal(err)
	}
	if released, err := state.ReleaseEndedHostRenewPending("nginx", "target-a", 11, 12); err != nil || released {
		t.Fatalf("a signed key was released: %v %v", released, err)
	}
	p, err := state.LoadHostRenewPending("nginx", "target-a", 11, binding(11))
	if err != nil || p == nil {
		t.Fatalf("the signed key is gone: %v", err)
	}
	if !bytes.Equal(p.CertPEM, []byte("cert")) {
		t.Fatalf("the signed slot changed")
	}
	// Nothing to release is not an error.
	if released, err := state.ReleaseEndedHostRenewPending("nginx", "target-b", 6, 7); err != nil || released {
		t.Fatalf("an empty target: %v %v", released, err)
	}
}
