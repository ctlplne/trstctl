// SPDX-License-Identifier: BUSL-1.1

package email_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/email"
)

// A258-L2: with named recipients the channel sends an alert addressed to one
// person to that person's own address alone (envelope and To:), and every
// other alert to its list; without the option, or with an address that is
// not a bare addr-spec, a named alert is refused and nothing is sent.
func TestEmailAddressesANamedRecipientA258L2(t *testing.T) {
	named := func(address string) notify.Alert {
		return notify.Alert{Kind: notify.KindEmergencyAccess, TenantID: "t1", Subject: "postgres/orders", Detail: "opened without approval",
			Recipient: &notify.AlertRecipient{Kind: "approver", Subject: "dana", DisplayName: "Dana", Email: address}}
	}
	fake := &fakeSender{}
	ch := email.New("smtp.example:587", "alerts@trstctl.example", []string{"oncall@example.com"}, email.WithSender(fake), email.WithNamedRecipients())
	if !ch.AddressesRecipients() {
		t.Fatal("the channel does not say it addresses named recipients")
	}
	if err := ch.Notify(context.Background(), named("dana@corp.example")); err != nil {
		t.Fatal(err)
	}
	if fake.Calls() != 1 || len(fake.to) != 1 || fake.to[0] != "dana@corp.example" || !strings.Contains(fake.Message(), "To: dana@corp.example\r\n") {
		t.Fatalf("the named alert went to %v", fake.to)
	}
	if err := ch.Notify(context.Background(), notify.Alert{Kind: notify.KindEmergencyAccess, TenantID: "t1", Subject: "postgres/orders"}); err != nil {
		t.Fatal(err)
	}
	if fake.Calls() != 2 || len(fake.to) != 1 || fake.to[0] != "oncall@example.com" {
		t.Fatalf("the unaddressed alert went to %v", fake.to)
	}
	for _, bad := range []string{"", "Dana <dana@corp.example>", "dana@corp.example\r\nRCPT TO:<x@evil.example>", "dana@corp.example,eve@evil.example",
		"dana@@corp.example", "dana corp@example", "\"dana\"@corp.example", strings.Repeat("a", 250) + "@x.example"} {
		if err := ch.Notify(context.Background(), named(bad)); err == nil {
			t.Fatalf("the address %q was sent to", bad)
		}
	}
	if fake.Calls() != 2 {
		t.Fatalf("a refused address still sent %d messages", fake.Calls()-2)
	}
	plain := email.New("smtp.example:587", "alerts@trstctl.example", []string{"oncall@example.com"}, email.WithSender(&fakeSender{}))
	if plain.AddressesRecipients() || plain.Notify(context.Background(), named("dana@corp.example")) == nil {
		t.Fatal("a channel without named recipients took a named alert")
	}
}
