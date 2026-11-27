// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCAAuthorityProjectionRequiresVisibleCommonName(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.CAAuthorityCreated{
		CAID: "00000000-0000-4000-8000-000000000809", CommonName: "  ", Kind: "root",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n",
		SignerHandle:   "test-signer", Serial: "ca-serial", NotAfter: time.Now().Add(24 * time.Hour),
		CeremonyID: "00000000-0000-4000-8000-000000000808",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = projections.New(st).Apply(ctx, events.Event{
		ID: "ca-name-validation", Type: projections.EventCARootCreated,
		TenantID: tenantA, SchemaVersion: projections.CAAuthorityCreatedEventSchemaVersion,
		Data: payload, Time: time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "common_name") {
		t.Fatalf("CA authority projection error = %v, want common_name validation", err)
	}
}
