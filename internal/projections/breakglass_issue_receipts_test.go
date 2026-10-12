// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/events"
)

func TestBreakglassIssueReceiptKeepsExactSignedBundleAndRejectsIncompleteOnlineEvent(t *testing.T) {
	bundle := breakglass.Bundle{RequestID: "incident-1", Subject: "recovery.test", CertDER: []byte{1, 2}, Reason: "outage", Approvals: []string{"custodian-a", "custodian-b"}, IssuedAt: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC), Signature: []byte{3, 4}}
	raw, _ := json.Marshal(struct {
		RequestID     string            `json:"request_id"`
		Subject       string            `json:"subject"`
		CeremonyID    string            `json:"ceremony_id"`
		RequestDigest string            `json:"request_digest"`
		Bundle        breakglass.Bundle `json:"bundle"`
	}{"incident-1", "recovery.test", "6f30d9bc-33d2-4f6d-af85-f789d9a8e2e0", "digest-1", bundle})
	event := events.Event{TenantID: "4a4a2bc7-e82e-40e5-8d06-a0954f8109c1", Sequence: 42, Data: raw}
	rec, online, err := breakglassIssueReceiptFromEvent(event)
	if err != nil || !online || rec.EventSequence != 42 || rec.CeremonyID == "" {
		t.Fatalf("receipt=%+v online=%v err=%v", rec, online, err)
	}
	var saved breakglass.Bundle
	if err := json.Unmarshal(rec.Bundle, &saved); err != nil || string(saved.Signature) != string(bundle.Signature) || string(saved.CertDER) != string(bundle.CertDER) {
		t.Fatalf("signed bundle changed: %+v err=%v", saved, err)
	}
	event.Data = []byte(`{"request_id":"offline","subject":"recovery.test","approvals":2}`)
	if _, online, err := breakglassIssueReceiptFromEvent(event); err != nil || online {
		t.Fatalf("offline audit event treated as online: online=%v err=%v", online, err)
	}
	event.Data = []byte(`{"request_id":"incident-1","subject":"recovery.test","bundle":{"cert_der":"AQID","signature":"BAUG"}}`)
	if _, online, err := breakglassIssueReceiptFromEvent(event); err == nil || online {
		t.Fatalf("signed issue without ceremony was accepted: online=%v err=%v", online, err)
	}
	event.Data = []byte(`{"request_id":"incident-1","subject":"recovery.test","ceremony_id":"6f30d9bc-33d2-4f6d-af85-f789d9a8e2e0","request_digest":"digest-1","bundle":{}}`)
	if _, online, err := breakglassIssueReceiptFromEvent(event); err == nil || online {
		t.Fatalf("incomplete online issue accepted: online=%v err=%v", online, err)
	}
}
