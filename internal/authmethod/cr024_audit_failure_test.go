// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestCR024MachineLoginWithholdsSessionWhenAuditAppendFails(t *testing.T) {
	tm := TokenMethod{Secret: []byte("fixture-auth-key"), TenantID: "t1", Scopes: map[string][]string{"app1": {"secrets:read"}}}
	token, err := tm.Issue("app1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	appendErr := errors.New("injected machine-login audit append failure")
	for _, tc := range []struct {
		name       string
		eventType  string
		credential []byte
	}{
		{name: "issued-session", eventType: "auth.session.issued", credential: []byte(token)},
		{name: "rejected-credential", eventType: "auth.rejected", credential: []byte("invalid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditor := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
				if eventType == tc.eventType {
					return appendErr
				}
				return nil
			})
			manager, err := New(Config{TenantID: "t1", Methods: []Method{tm}, Audit: auditor})
			if err != nil {
				t.Fatal(err)
			}
			session, err := manager.Login(t.Context(), "token", tc.credential)
			if !errors.Is(err, appendErr) || session.ID != "" {
				t.Fatalf("machine login hid audit outage: session_present=%t err=%v", session.ID != "", err)
			}
		})
	}
}
