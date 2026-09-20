// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/signing"
)

type buildAdmissionObserver struct{ admit func(func() error) error }

func (*buildAdmissionObserver) Client() *signing.Client                       { return nil }
func (s *buildAdmissionObserver) SetAdmission(admit func(func() error) error) { s.admit = admit }

// A failed Build returns no Server to shut down. Its own resources must close,
// while an injected pool remains the caller's resource on this failed path.
func TestFailedBuildReleasesOwnedPoolsAndPreservesInjectedPools(t *testing.T) {
	for _, injected := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "injected"}[injected], func(t *testing.T) {
			st, log := notificationOwnershipTestStack(t)
			observer := &buildAdmissionObserver{}
			wantErr := errors.New("late construction failure")
			called := false
			deps := Deps{Store: st, Log: log, Signer: observer, LicensedOutboxFactory: func(LicensedOutboxDeps) (LicensedOutboxHandler, error) { called = true; return nil, wantErr }}
			if injected {
				deps.Bulkhead = bulkhead.Default()
				t.Cleanup(deps.Bulkhead.Close)
			}
			server, err := Build(t.Context(), deps)
			if !called || server != nil || !errors.Is(err, wantErr) || observer.admit == nil {
				t.Fatalf("did not reach post-pool failure: called=%v server=%v err=%v admission=%v", called, server, err, observer.admit != nil)
			}
			ran := false
			err = observer.admit(func() error { ran = true; return nil })
			if injected {
				if err != nil || !ran {
					t.Fatalf("failed Build closed caller's pool: ran=%v err=%v", ran, err)
				}
				return
			}
			var refusal *bulkhead.Rejected
			if ran || !errors.As(err, &refusal) || refusal.Reason != bulkhead.ReasonClosed {
				t.Fatalf("failed Build retained its pool: ran=%v err=%v", ran, err)
			}
		})
	}
}
