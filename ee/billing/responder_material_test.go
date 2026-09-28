// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestResponderFactsRequireLeafMaterialAndExactBackfill(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_responder_material")
	log, projector, _ := billingHistory(t, cs)
	leaf := billingMintedCertificate(t, "issued", "material-leaf")
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	caDER, err := crypto.SelfSignedCACert(key, "excluded-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                      string
		der                       []byte
		fingerprint, serial, want string
	}{
		{"leaf", leaf.CertificateDER, leaf.Fingerprint, leaf.Serial, "mint"},
		{"missing", nil, leaf.Fingerprint, leaf.Serial, "unverifiable"},
		{"invalid", []byte("not a certificate"), leaf.Fingerprint, leaf.Serial, "unverifiable"},
		{"wrong fingerprint", leaf.CertificateDER, "different", leaf.Serial, "unverifiable"},
		{"wrong serial", leaf.CertificateDER, leaf.Fingerprint, "different", "unverifiable"},
		{"authority", caDER, caInfo.SHA256Fingerprint, caInfo.SerialNumber, "not_mint"},
	}
	var first events.Event
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(projections.CAIssuedCertificate{CAID: uuid.NewString(), Serial: tc.serial, CertificateDER: tc.der, Fingerprint: tc.fingerprint})
			if err != nil {
				t.Fatal(err)
			}
			e, err := log.Append(t.Context(), events.Event{Type: projections.EventCAIssuedCertificate, SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, TenantID: quotaTenant, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if err := projector.Apply(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := cs.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
				return tx.QueryRow(t.Context(), `SELECT issuance_status FROM certificate_metadata_receipts WHERE tenant_id=$1 AND event_id=$2`, quotaTenant, e.ID).Scan(&status)
			}); err != nil {
				t.Fatal(err)
			}
			if status != tc.want {
				t.Errorf("receipt status=%s want=%s", status, tc.want)
			}
			if tc.name == "leaf" {
				first = e
			}
		})
	}
	if n, known, err := pg.IssuedInPeriod(t.Context(), quotaTenant, first.Time.Add(-time.Second), time.Now().UTC().Add(time.Second)); err != nil || known || n != 1 {
		t.Errorf("mixed evidence count=%d known=%t error=%v; want one leaf and unverified history", n, known, err)
	}
	if err := cs.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE certificate_metadata_receipts SET issuance_status=NULL,issuance_fingerprint=NULL,issuance_time=NULL WHERE tenant_id=$1 AND event_id=$2`, quotaTenant, first.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.Data = append(append([]byte(nil), first.Data[:len(first.Data)-1]...), []byte(`,"subject":"different"}`)...)
	err = cs.BackfillCertificateIssuanceReceipt(t.Context(), changed, func() (corestore.CertificateIssuanceReceipt, error) {
		return corestore.CertificateIssuanceReceipt{Status: "not_mint"}, nil
	})
	if !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Errorf("changed source accepted for backfill: %v", err)
	}
	if err := projector.ProjectCatchUp(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	var restored string
	if err := cs.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT issuance_status FROM certificate_metadata_receipts WHERE tenant_id=$1 AND event_id=$2`, quotaTenant, first.ID).Scan(&restored)
	}); err != nil {
		t.Fatal(err)
	}
	if restored != "mint" {
		t.Errorf("exact retained source restored %s, want mint", restored)
	}
}
