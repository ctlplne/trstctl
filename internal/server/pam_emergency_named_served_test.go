// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	notifyemail "trstctl.com/trstctl/internal/notify/email"
)

// a258l2Mail is the deployment's SMTP relay: it keeps every message the
// email channel sends and to whom.
type a258l2Mail struct {
	mu   sync.Mutex
	sent []a258l2Message
}

type a258l2Message struct {
	to  []string
	msg string
}

// Send keeps the message's headers and its quoted-printable body decoded.
func (m *a258l2Mail) Send(_ context.Context, _ string, to []string, msg []byte) error {
	headers, body, _ := strings.Cut(string(msg), "\r\n\r\n")
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, a258l2Message{to: append([]string(nil), to...), msg: headers + "\r\n\r\n" + string(decoded)})
	return nil
}

// to is every message sent to exactly address that names the grant's reason.
func (m *a258l2Mail) to(address, reason string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, s := range m.sent {
		if len(s.to) == 1 && s.to[0] == address && strings.Contains(s.msg, reason) {
			out = append(out, s.msg)
		}
	}
	return out
}

// TestServedEmergencyAccessNotifiesEachApproverByNameA258L2 is A258-L2's
// Done-when (served, the gateway fixture, the operator's email channel with
// named recipients behind a capturing SMTP relay): emergency access opened by
// a named responder notifies, beside the approval-channel notice to the
// channel's list, each approver by name at their own address — the active
// members whose roles grant access:approve, with an address, not the
// responder. A member without an address, a viewer and the responder get
// none. The grant names whom it notified (the open's answer and the grants
// list). The notice reconciler, run again, sends no approver a second notice.
func TestServedEmergencyAccessNotifiesEachApproverByNameA258L2(t *testing.T) {
	mail := &a258l2Mail{}
	channel := notifyemail.New("smtp.invalid:587", "alerts@trstctl.example", []string{"approvals-a258l2@corp.example"},
		notifyemail.WithSender(mail), notifyemail.WithNamedRecipients())
	f := startGatewayFixture(t, gatewayFixtureOptions{notificationChannels: []notify.Notifier{channel}})
	h := f.h
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a258l2-admin", "*")
	member := func(subject, email string, roles ...string) {
		t.Helper()
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/members/"+subject, admin, "a258l2-member-"+subject,
			map[string]any{"display_name": strings.Split(subject, "-")[0], "email": email, "roles": roles, "source": "manual"}); status != http.StatusOK {
			t.Fatalf("member %s = %d %s", subject, status, body)
		}
	}
	const responderSubject = "oncall-a258l2@ops.example"
	member("dana-a258l2", "dana.a258l2@corp.example", "operator")
	member("eli-a258l2", "eli.a258l2@corp.example", "operator")
	member("fay-a258l2", "", "operator")
	member("gus-a258l2", "gus.a258l2@corp.example", "viewer")
	member(responderSubject, "oncall.a258l2@ops.example", "operator")
	responder := seedScopedTokenSubject(t, h.store, h.tenant, responderSubject, "access:read", "access:sessions.open")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/emergency/responders", admin, "a258l2-responders",
		map[string]any{"subjects": []string{responderSubject}}); status != http.StatusOK {
		t.Fatalf("name the responder = %d %s", status, body)
	}

	const reason = "orders primary refusing writes (A258-L2)"
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/emergency-sessions", responder, "a258l2-emergency", map[string]any{
		"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "reason": reason,
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 20})
	var opened struct {
		ID        string `json:"id"`
		Emergency struct {
			NotifiedApprovers []string `json:"notified_approvers"`
		} `json:"emergency"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &opened) != nil {
		t.Fatalf("emergency open = %d %s", status, body)
	}
	notified := opened.Emergency.NotifiedApprovers
	if !slices.Contains(notified, "dana-a258l2") || !slices.Contains(notified, "eli-a258l2") ||
		slices.Contains(notified, "fay-a258l2") || slices.Contains(notified, "gus-a258l2") || slices.Contains(notified, responderSubject) {
		t.Fatalf("the grant notified %v; want dana and eli, not fay (no address), gus (a viewer) or the responder", notified)
	}

	drain := func() {
		t.Helper()
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	drain()
	a201Await(t, "each approver's notice and the channel notice are sent", func() bool {
		drain()
		return len(mail.to("dana.a258l2@corp.example", reason)) == 1 && len(mail.to("eli.a258l2@corp.example", reason)) == 1 &&
			len(mail.to("approvals-a258l2@corp.example", reason)) == 1
	})
	for _, address := range []string{"dana.a258l2@corp.example", "eli.a258l2@corp.example"} {
		msg := mail.to(address, reason)[0]
		if !strings.Contains(msg, "To: "+address+"\r\n") || !strings.Contains(msg, "You are notified as an approver") || !strings.Contains(msg, responderSubject) {
			t.Fatalf("the notice to %s reads:\n%s", address, msg)
		}
	}
	for _, address := range []string{"gus.a258l2@corp.example", "oncall.a258l2@ops.example"} {
		if got := mail.to(address, reason); len(got) != 0 {
			t.Fatalf("%s was notified %d times", address, len(got))
		}
	}

	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/emergency-sessions", admin, nil)
	var grants struct {
		Items []struct {
			SessionID         string   `json:"session_id"`
			NotifiedApprovers []string `json:"notified_approvers"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &grants) != nil {
		t.Fatalf("grants = %d %s", status, body)
	}
	listed := false
	for _, g := range grants.Items {
		listed = listed || (g.SessionID == opened.ID && slices.Equal(g.NotifiedApprovers, notified))
	}
	if !listed {
		t.Fatalf("the grants list does not name whom %s notified: %s", opened.ID, body)
	}

	// The reconciler (a crash between the grant and its notices) queues
	// nothing already queued: no approver gets a second notice.
	h.srv.pam.reconcileEmergencyNotices(t.Context())
	drain()
	drain()
	if len(mail.to("dana.a258l2@corp.example", reason)) != 1 || len(mail.to("eli.a258l2@corp.example", reason)) != 1 {
		t.Fatal("the reconciler sent an approver a second notice")
	}
	t.Logf("A258L2_OK grant=%s notified=%s", opened.ID, strings.Join(notified, ","))
}
