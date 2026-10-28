// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// The immutable log returns its first writer on duplicate IDs. A race at
// completion must not turn a different canonical receipt into a delivered row.
func TestCMDBExportCompletionChecksItsCanonicalFirstWriter(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	command := cmdbexport.Command{ID: uuid.NewString(), CertificateID: uuid.NewString(), Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", BindingID: "certificate-writer", BindingDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	expected := cmdbexport.Receipt{OperationID: command.ID, CertificateID: command.CertificateID, Fingerprint: command.Fingerprint, BindingID: command.BindingID, BindingDigest: command.BindingDigest, CertificateStatus: "active", SystemID: "0123456789abcdef0123456789abcdef", ValuesDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", CheckedAt: time.Now().UTC()}
	corrupt := expected
	corrupt.BindingID = "different-writer"
	body, err := json.Marshal(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.log.Append(context.Background(), events.Event{ID: cmdbReceiptID(command.ID), TenantID: h.tenant, Type: cmdbexport.EventVerified, Data: body}); err != nil {
		t.Fatal(err)
	}
	if err = h.srv.cmdbExports.appendReceipt(t.Context(), h.tenant, command, expected); err == nil {
		t.Fatal("completion accepted a different canonical receipt")
	}
	command.ID = uuid.NewString()
	expected.OperationID = command.ID
	if err = h.srv.cmdbExports.appendReceipt(t.Context(), h.tenant, command, expected); err != nil {
		t.Fatal(err)
	}
	expected.CheckedAt = expected.CheckedAt.Add(time.Second)
	if err = h.srv.cmdbExports.appendReceipt(t.Context(), h.tenant, command, expected); err != nil {
		t.Fatalf("same verified effect replay: %v", err)
	}
	expected.ValuesDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err = h.srv.cmdbExports.appendReceipt(t.Context(), h.tenant, command, expected); err == nil {
		t.Fatal("accepted another effect under the same receipt identity")
	}
}
