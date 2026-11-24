// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	_ "trstctl.com/trstctl/ee" // register the licensed privacy catalog, as the served binary does
	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/ee/provider"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
)

type cr143NoKeys struct{}

func (cr143NoKeys) WithKey(context.Context, eventprotect.KeyRef, func(seal.KeyWrapper) error) error {
	return errors.New("CR-143: Provider public control must not request a tenant key")
}

func TestCR143PreProtectionProviderOperatorCanBeDeprovisionedAfterUpgrade(t *testing.T) {
	ctx := t.Context()
	st := provider.CR143TestStore(t)
	nats := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}
	before, err := eventstest.OpenFixture(ctx, nats, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	preUpgrade := provider.NewAuthorityRuntime(st, before)
	create := `{"schemas":["` + scim.SchemaUser + `"],"externalId":"cr143-subject","userName":"cr143@example.test","active":true}`
	code, body := provider.CR143TestSCIM(t, st, preUpgrade)(http.MethodPost, "/provider/scim/v2/Users", create)
	if code != http.StatusCreated {
		_ = before.Close()
		t.Fatalf("pre-upgrade Provider operator create: HTTP %d %s", code, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID == "" {
		_ = before.Close()
		t.Fatalf("pre-upgrade Provider operator ID: %v %s", err, body)
	}
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := eventstest.OpenFixture(ctx, nats, events.WithRequiredPrivacyEventPolicies(),
		events.WithEventProtection(events.EventProtection{Admission: eventprivacy.SourceAdmission{Guard: st}, Keys: cr143NoKeys{}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = after.Close() })
	upgraded := provider.NewAuthorityRuntime(st, after)
	if err := upgraded.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap the upgraded Provider authority: %v", err)
	}
	identity, err := provider.NewPGAccessStore(st).ResolveOperator(ctx, created.ID)
	if err != nil || !identity.Active {
		t.Fatalf("upgrade precondition: operator active=%v err=%v", identity.Active, err)
	}
	code, body = provider.CR143TestSCIM(t, st, upgraded)(http.MethodDelete, "/provider/scim/v2/Users/"+created.ID, "")
	identity, err = provider.NewPGAccessStore(st).ResolveOperator(ctx, created.ID)
	if code != http.StatusNoContent || err != nil || identity.Active {
		t.Fatalf("post-upgrade deprovision: HTTP %d %s; operator active=%v err=%v", code, body, identity.Active, err)
	}
}
