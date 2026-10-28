// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"io"
	"net/mail"
	"strings"
	"testing"
)

func FuzzConfiguredTicketOwnerRemainsABoundedMailbox(f *testing.F) {
	f.Add(false, `{"result":[{"sys_id":"row1","assigned_to.email":"ops@example.test"}]}`)
	f.Add(true, `{"issues":[{"id":"1","fields":{"assignee":{"displayName":"ops@example.test"}}}],"isLast":true}`)
	f.Fuzz(func(t *testing.T, jira bool, body string) {
		intent := SyncIntent{System: "servicenow", OwnerField: "assigned_to.email", SubjectField: "u_subject", ProfileField: "u_profile", PageLimit: 100}
		if jira {
			intent.System = "jira"
			intent.OwnerField = "assignee.emailAddress"
		}
		page, err := ParsePage(io.LimitReader(strings.NewReader(body), 1<<20), intent)
		if err != nil {
			return
		}
		if len(page.Tickets) > MaxTickets {
			t.Fatal("owner parser escaped the page bound")
		}
		for _, ticket := range page.Tickets {
			if ticket.OwnerEmail == "" {
				continue
			}
			address, err := mail.ParseAddress(ticket.OwnerEmail)
			if err != nil || address.Address != ticket.OwnerEmail || len(ticket.OwnerEmail) > 320 || strings.ToLower(strings.TrimSpace(ticket.OwnerEmail)) != ticket.OwnerEmail {
				t.Fatalf("noncanonical mapped mailbox %q", ticket.OwnerEmail)
			}
		}
	})
}
