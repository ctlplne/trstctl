// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type edgeBuildSigner struct{}

func (edgeBuildSigner) Client() *signing.Client { return &signing.Client{} }

type edgeBuildAuthz struct{}

func (edgeBuildAuthz) Authorize(crypto.SignIntent) ([]byte, error) { return nil, nil }

// Building the edge delegation service only builds it: the server keeps it for
// the agent channel's journal reconciliation (A219) where the API options are
// assembled, in plain sight, not as a side effect of the builder (42d025a46).
func TestBuildEdgeDelegationServiceOnlyReturnsTheService(t *testing.T) {
	s := &Server{signAuthz: edgeBuildAuthz{}}
	svc := s.buildEdgeDelegationService(Deps{Store: &store.Store{}, Signer: edgeBuildSigner{}}, &orchestrator.Orchestrator{})
	if svc == nil {
		t.Fatal("a fully configured build returned no service")
	}
	if s.edgeDelegations != nil {
		t.Fatal("the builder set the server's edge delegation field; the caller assigns it")
	}
}
