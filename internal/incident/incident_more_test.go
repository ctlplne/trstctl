package incident

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestIncidentNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	if _, err := New(Config{TenantID: "t1"}); err == nil {
		t.Error("missing Graph accepted")
	}
}

func TestRemediateMissingIdempotencyKey(t *testing.T) {
	w := newWF(t, seed(), &fakeRem{}, nil)
	if _, err := w.Remediate(context.Background(), "credA", ""); err == nil {
		t.Error("missing Idempotency-Key accepted")
	}
}

func TestRemediateReissueFailureIsRecoverable(t *testing.T) {
	rem := &fakeRem{failReissue: map[string]bool{"credA": true}}
	rep, err := newWF(t, seed(), rem, &auditsink.Recorder{}).Remediate(context.Background(), "credA", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Completed {
		t.Error("report marked complete despite a reissue failure")
	}
	for _, s := range rep.Steps {
		if s.CredentialID == "credA" {
			if s.Reissued != "" {
				t.Error("credA reported reissued despite the injected failure")
			}
			if !s.HasValidCredential {
				t.Error("credA left without a valid credential after a reissue failure (should be unchanged)")
			}
		}
	}
}
