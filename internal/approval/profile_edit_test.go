package approval

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestProfileEditApprovalKindAndPayloadAreRecorded(t *testing.T) {
	m := newMgr(t, &recIssuer{}, nil, nil, &auditsink.Recorder{}, nil)
	payload := json.RawMessage(`{"name":"web","requires_approval":true}`)

	req, err := m.RequestIssuance(context.Background(), RequestSpec{
		ID:        "profile-edit-1",
		Kind:      KindProfileEdit,
		Resource:  "profile:web",
		Requester: "alice",
		Payload:   payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Kind != KindProfileEdit {
		t.Fatalf("kind = %q, want %q", req.Kind, KindProfileEdit)
	}
	if string(req.Payload) != string(payload) {
		t.Fatalf("payload = %s, want %s", req.Payload, payload)
	}
}
