// SPDX-License-Identifier: BUSL-1.1

package notify_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/notify"
)

// addressingNotifier is a channel that addresses named recipients.
type addressingNotifier struct{ capturingNotifier }

func (*addressingNotifier) AddressesRecipients() bool { return true }

// A258-L2: an alert addressed to one person goes only to the channels that
// address people, whatever the routing; with none it has no receiver.
func TestNamedRecipientAlertsGoOnlyToAddressingChannelsA258L2(t *testing.T) {
	plain := &capturingNotifier{name: "chat"}
	addressing := &addressingNotifier{capturingNotifier{name: "email"}}
	d := notify.NewDispatcher(plain, addressing)
	named, _ := json.Marshal(notify.Alert{Kind: notify.KindEmergencyAccess, TenantID: "t1", Subject: "postgres/orders",
		Recipient: &notify.AlertRecipient{Kind: "approver", Subject: "dana", Email: "dana@corp.example"}})
	if err := d.Dispatch(context.Background(), named); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(plain.got) != 0 || len(addressing.got) != 1 || addressing.got[0].Recipient == nil || addressing.got[0].Recipient.Email != "dana@corp.example" {
		t.Fatalf("a named alert reached chat %d times and email %d times", len(plain.got), len(addressing.got))
	}
	channel, _ := json.Marshal(notify.Alert{Kind: notify.KindEmergencyAccess, TenantID: "t1", Subject: "postgres/orders"})
	if err := d.Dispatch(context.Background(), channel); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(plain.got) != 1 || len(addressing.got) != 2 {
		t.Fatalf("an unaddressed alert reached chat %d times and email %d times, want both", len(plain.got), len(addressing.got)-1)
	}
	if err := notify.NewDispatcher(plain).Dispatch(context.Background(), named); err == nil {
		t.Fatal("a named alert with no addressing channel was delivered")
	}
	if notify.AddressesRecipients([]notify.Notifier{plain}) || !notify.AddressesRecipients([]notify.Notifier{plain, addressing}) {
		t.Fatal("AddressesRecipients misread the channels")
	}
}
