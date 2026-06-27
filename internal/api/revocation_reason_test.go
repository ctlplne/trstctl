package api

import (
	"errors"
	"net/http"
	"testing"
)

func TestTransitionIdentityRejectsUnknownRevocationReason(t *testing.T) {
	err := validateTransitionRequest(transitionRequest{
		To:     "revoked",
		Reason: "operator typed a paragraph",
	})
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("validateTransitionRequest error = %v, want apiError", err)
	}
	if ae.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", ae.status)
	}
}

func TestTransitionIdentityAllowsRFC5280RevocationReason(t *testing.T) {
	if err := validateTransitionRequest(transitionRequest{To: "revoked", Reason: "keyCompromise"}); err != nil {
		t.Fatalf("keyCompromise rejected: %v", err)
	}
	if err := validateTransitionRequest(transitionRequest{To: "revoked"}); err != nil {
		t.Fatalf("empty revocation reason should default to unspecified: %v", err)
	}
	if err := validateTransitionRequest(transitionRequest{To: "issued", Reason: "operator free-form text"}); err != nil {
		t.Fatalf("non-revocation transition reason should remain free-form: %v", err)
	}
}
