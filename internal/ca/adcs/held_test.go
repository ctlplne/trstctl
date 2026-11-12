// SPDX-License-Identifier: BUSL-1.1

package adcs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/ca/adcs/adcsfake"
)

// TestHeldRequestCarriesItsRequestIDAndReadsBackN1L1 is N1-L1 at the plugin: a
// request the CA holds past the plugin's polls fails with the CA's request id;
// reading it back by that id answers held while the CA holds it, the issued
// certificate once a manager approves it (the same one when read again), and
// the CA's refusal once a manager denies it.
func TestHeldRequestCarriesItsRequestIDAndReadsBackN1L1(t *testing.T) {
	ctx := context.Background()
	tr, err := adcsfake.NewTransport()
	if err != nil {
		t.Fatal(err)
	}
	tr.SetHoldForApproval(true)
	plugin := adcs.New(config("contoso"), tr, adcs.WithPollInterval(time.Millisecond))

	_, err = plugin.Issue(ctx, ca.IssueRequest{CSR: adcsCSR(t, "held.contoso.local"), DNSNames: []string{"held.contoso.local"}})
	id, held := ca.HeldRequestID(err)
	if !held || id != 1 || !errors.Is(err, ca.ErrIssuanceHeld) {
		t.Fatalf("an issuance the CA holds = %v; want a held error for request 1", err)
	}
	if _, err := ca.RetrieveHeldThrough(ctx, plugin, id); !errors.Is(err, ca.ErrIssuanceHeld) {
		t.Fatalf("read back while held = %v", err)
	}
	if !tr.Approve(id) {
		t.Fatal("the CA did not hold request 1")
	}
	issued, err := ca.RetrieveHeldThrough(ctx, plugin, id)
	if err != nil || issued.Serial == "" || len(issued.CertificatePEM) == 0 {
		t.Fatalf("read back after approval = %+v, %v", issued, err)
	}
	if again, err := ca.RetrieveHeldThrough(ctx, plugin, id); err != nil || again.Serial != issued.Serial {
		t.Fatalf("read back again = %+v, %v; want the same certificate", again, err)
	}

	_, err = plugin.Issue(ctx, ca.IssueRequest{CSR: adcsCSR(t, "denied.contoso.local"), DNSNames: []string{"denied.contoso.local"}})
	denied, held := ca.HeldRequestID(err)
	if !held || denied != 2 || !tr.Deny(denied) {
		t.Fatalf("second held issuance = %v", err)
	}
	if _, err := ca.RetrieveHeldThrough(ctx, plugin, denied); !errors.Is(err, ca.ErrRequestRefused) || errors.Is(err, ca.ErrIssuanceHeld) {
		t.Fatalf("read back after denial = %v; want the CA's refusal", err)
	}
	if _, err := ca.RetrieveHeldThrough(ctx, plugin, 0); err == nil {
		t.Fatal("a read back with no request id was accepted")
	}
}
