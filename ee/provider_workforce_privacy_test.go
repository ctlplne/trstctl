// SPDX-License-Identifier: LicenseRef-trstctl-EE

package ee_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/provider"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/store"
)

func TestProviderWorkforceEventsPassRequiredPrivacyBoundary(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const subject = "workforce@example.test"
	for _, typ := range []string{provider.EventOperatorUpserted, provider.EventOperatorOffboarded} {
		t.Run(typ, func(t *testing.T) {
			now := time.Now().UTC()
			payload := provider.AuthorityEvent{
				Operator: &provider.OperatorIdentity{
					ID: subject, ExternalID: subject, UserName: subject, Email: subject,
					DisplayName: "Operator " + subject, Role: provider.OperatorAdmin,
					Active: typ == provider.EventOperatorUpserted, Source: "scim:workforce",
					CreatedAt: now, UpdatedAt: now,
				},
				EffectiveAt: now,
				Audit: provider.AuditEvent{Type: typ, TenantID: store.ZeroUUID,
					OperatorID: "scim:workforce", Subject: subject, At: now},
			}
			if !payload.Operator.Active {
				payload.Operator.DeprovisionedAt = now
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(t.Context(), events.Event{TenantID: store.ZeroUUID, Type: typ, Data: raw}); err != nil {
				t.Fatalf("production-required privacy boundary rejected workforce event: %v", err)
			}
			rewritten, changed, err := events.PseudonymizeEventDataForSubject(raw, store.ZeroUUID, subject, typ, 1)
			if err != nil || !changed || bytes.Contains(rewritten, []byte(subject)) {
				t.Fatalf("workforce privacy rewrite failed: changed=%t err=%v", changed, err)
			}
			var decoded provider.AuthorityEvent
			if err := json.Unmarshal(rewritten, &decoded); err != nil || decoded.Operator == nil {
				t.Fatalf("rewritten workforce authority no longer decodes: %v", err)
			}
			want := privacyref.Placeholder(privacyref.SubjectRef(store.ZeroUUID, subject))
			if decoded.Operator.ID != want || decoded.Operator.ExternalID != want || decoded.Operator.UserName != want || decoded.Operator.Email != want || decoded.Audit.Subject != want {
				t.Fatal("workforce identity fields did not retain consistent pseudonymous references")
			}
			if decoded.Operator.Active != payload.Operator.Active || decoded.Operator.Role != payload.Operator.Role || !decoded.Operator.DeprovisionedAt.Equal(payload.Operator.DeprovisionedAt) {
				t.Fatal("privacy rewrite changed workforce lifecycle authority")
			}
			var drift map[string]any
			if err := json.Unmarshal(raw, &drift); err != nil {
				t.Fatal(err)
			}
			drift["operator"].(map[string]any)["unreviewed_personal_field"] = subject
			unknown, err := json.Marshal(drift)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(t.Context(), events.Event{TenantID: store.ZeroUUID, Type: typ, Data: unknown}); err == nil {
				t.Fatal("unreviewed nested workforce field bypassed the closed privacy policy")
			}
		})
	}
}
