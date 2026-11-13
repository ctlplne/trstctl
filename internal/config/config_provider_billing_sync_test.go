// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// MSP-2: a billing target needs a clean unique ID, a type this build pushes
// to, an absolute https endpoint without embedded credentials (http only for
// a loopback test receiver), an HMAC signing key reference, optional bearer
// reference, a monthly or daily cadence, and named CIDRs for a private
// endpoint. Every valid shape is accepted.
func TestProviderBillingSyncTargetsMSP2(t *testing.T) {
	valid := ProviderBillingTarget{ID: "psa-main", Type: "json", Endpoint: "https://billing.example.test/usage", // #nosec G101 -- file: and env: references to test-only values (CWE-798)
		SigningKeyRef: "file:/run/secrets/billing-hmac", TokenRef: "env:TRSTCTL_BILLING_TOKEN"}
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}); len(errs) != 0 {
		t.Fatalf("valid target refused: %v", errs)
	}
	if valid.EffectiveCadence() != "monthly" {
		t.Fatalf("default cadence = %q", valid.EffectiveCadence())
	}
	loopback := valid
	loopback.Endpoint, loopback.AllowInsecureLoopback, loopback.Cadence = "http://127.0.0.1:9000/usage", true, "daily"
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{loopback}}); len(errs) != 0 {
		t.Fatalf("loopback test receiver refused: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"upper-case id":       {func(t *ProviderBillingTarget) { t.ID = "PSA" }, ".id"},
		"empty id":            {func(t *ProviderBillingTarget) { t.ID = "" }, ".id"},
		"unknown type":        {func(t *ProviderBillingTarget) { t.Type = "csv-upload" }, ".type"},
		"relative endpoint":   {func(t *ProviderBillingTarget) { t.Endpoint = "/usage" }, ".endpoint"},
		"plain http":          {func(t *ProviderBillingTarget) { t.Endpoint = "http://billing.example.test/usage" }, ".endpoint"},
		"credentials in url":  {func(t *ProviderBillingTarget) { t.Endpoint = "https://user:pw@billing.example.test/usage" }, ".endpoint"},
		"no signing key":      {func(t *ProviderBillingTarget) { t.SigningKeyRef = "" }, ".signing_key_ref"},
		"inline signing key":  {func(t *ProviderBillingTarget) { t.SigningKeyRef = "hunter2" }, ".signing_key_ref"},
		"inline token":        {func(t *ProviderBillingTarget) { t.TokenRef = "abc123" }, ".token_ref"},
		"tenant secret token": {func(t *ProviderBillingTarget) { t.TokenRef = "secret://integrations/billing" }, ".token_ref"},
		"weekly cadence":      {func(t *ProviderBillingTarget) { t.Cadence = "weekly" }, ".cadence"},
		"private without cidrs": {func(t *ProviderBillingTarget) {
			t.AllowPrivateEndpoint = true
		}, "private_egress_cidrs"},
		"long name": {func(t *ProviderBillingTarget) { t.Name = strings.Repeat("n", 129) }, ".name"},
	} {
		target := valid
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, errs, tc.want)
		}
	}
	dup := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid, valid}})
	if len(dup) == 0 || !strings.Contains(dup[0].Error(), "listed twice") {
		t.Fatalf("duplicate id: %v", dup)
	}
	if got, ok := (ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}).Target("psa-main"); !ok || got.Endpoint != valid.Endpoint {
		t.Fatalf("Target lookup = %+v %v", got, ok)
	}
}

// MSP-3: a connectwise target names the PSA login company, the integration's
// clientId GUID, both API member keys as deployment references, the agreement
// type and at least one meter's catalog product; a value that would need
// escaping inside a conditions query is refused, and json-only fields are
// refused on it (and its block on a json target).
func TestProviderBillingSyncConnectWiseTargetMSP3(t *testing.T) {
	valid := ProviderBillingTarget{ID: "cw", Type: "connectwise", Endpoint: "https://api-na.myconnectwise.net/v4_6_release/apis/3.0",
		ConnectWise: &ConnectWiseBillingTarget{CompanyID: "trstctl_msp", ClientID: "6c1a3e1e-58e3-4d1b-9f0e-3b8f5a0c2d71",
			PublicKeyRef: "env:TRSTCTL_CW_PUBLIC", PrivateKeyRef: "file:/run/secrets/cw-private", // #nosec G101 -- env: and file: references to test-only values (CWE-798)
			AgreementType: "Managed PKI", Products: map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}}}
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{valid}}); len(errs) != 0 {
		t.Fatalf("valid connectwise target refused: %v", errs)
	}
	clone := func() ProviderBillingTarget {
		c := valid
		cw := *valid.ConnectWise
		cw.Products = map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}
		c.ConnectWise = &cw
		return c
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":             {func(t *ProviderBillingTarget) { t.ConnectWise = nil }, ".connectwise is required"},
		"signing key":          {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"bearer":               {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"login company":        {func(t *ProviderBillingTarget) { t.ConnectWise.CompanyID = "a b" }, ".company_id"},
		"client id":            {func(t *ProviderBillingTarget) { t.ConnectWise.ClientID = "not-a-guid" }, ".client_id"},
		"inline public key":    {func(t *ProviderBillingTarget) { t.ConnectWise.PublicKeyRef = "abc123" }, ".public_key_ref"},
		"tenant private key":   {func(t *ProviderBillingTarget) { t.ConnectWise.PrivateKeyRef = "secret://cw/private" }, ".private_key_ref"},
		"quoted agreement":     {func(t *ProviderBillingTarget) { t.ConnectWise.AgreementType = `PKI" or name="x` }, ".agreement_type"},
		"no products":          {func(t *ProviderBillingTarget) { t.ConnectWise.Products = nil }, ".products must map"},
		"unknown meter":        {func(t *ProviderBillingTarget) { t.ConnectWise.Products["certificates_issued"] = "X" }, "not a pushed meter"},
		"quoted product":       {func(t *ProviderBillingTarget) { t.ConnectWise.Products["agents"] = `A"B` }, ".products.agents"},
		"block on a json type": {func(t *ProviderBillingTarget) { t.Type, t.SigningKeyRef = "json", "env:X" }, "connectwise targets only"},
	} {
		target := clone()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-4: an autotask target names the API user, its secret and tracking
// identifier as deployment references, at least one meter's service ID, and
// for tickets two different status values and a priority; json and
// connectwise fields are refused on it, and its block on other types.
func TestProviderBillingSyncAutotaskTargetMSP4(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "at", Type: "autotask", Endpoint: "https://webservices3.autotask.net/atservicesrest/v1.0",
			Autotask: &AutotaskBillingTarget{Username: "trstctl-api@msp.example", SecretRef: "file:/run/secrets/at-secret", // #nosec G101 -- file: and env: references to test-only values (CWE-798)
				IntegrationCodeRef: "env:TRSTCTL_AT_CODE", Services: map[string]int64{"certificates_current": 29683501},
				Tickets: &AutotaskTickets{StatusNew: 1, StatusComplete: 5, Priority: 2}}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid autotask target refused: %v", errs)
	}
	if kinds := ok.TicketKinds(); len(kinds) != len(PSATicketAlertKinds) {
		t.Fatalf("ticket kinds = %v, want all", kinds)
	}
	if ok.Autotask.Tickets.EffectiveNoteType() != 1 || ok.Autotask.Tickets.EffectiveNotePublish() != 1 {
		t.Fatal("note picklists do not default to 1")
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":           {func(t *ProviderBillingTarget) { t.Autotask = nil }, ".autotask is required"},
		"signing key":        {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"connectwise block":  {func(t *ProviderBillingTarget) { t.ConnectWise = &ConnectWiseBillingTarget{} }, "connectwise targets only"},
		"no user":            {func(t *ProviderBillingTarget) { t.Autotask.Username = "" }, ".username"},
		"inline secret":      {func(t *ProviderBillingTarget) { t.Autotask.SecretRef = "hunter2" }, ".secret_ref"},
		"tenant code":        {func(t *ProviderBillingTarget) { t.Autotask.IntegrationCodeRef = "secret://at/code" }, ".integration_code_ref"},
		"no services":        {func(t *ProviderBillingTarget) { t.Autotask.Services = nil }, ".services must map"},
		"unknown meter":      {func(t *ProviderBillingTarget) { t.Autotask.Services["certificates_issued"] = 1 }, "not a pushed meter"},
		"zero service":       {func(t *ProviderBillingTarget) { t.Autotask.Services["agents"] = 0 }, ".services.agents"},
		"same statuses":      {func(t *ProviderBillingTarget) { t.Autotask.Tickets.StatusComplete = 1 }, "two different"},
		"no priority":        {func(t *ProviderBillingTarget) { t.Autotask.Tickets.Priority = 0 }, ".tickets.priority"},
		"unknown kind":       {func(t *ProviderBillingTarget) { t.Autotask.Tickets.Kinds = []string{"ca.horizon"} }, "not a ticketed alert kind"},
		"block on json type": {func(t *ProviderBillingTarget) { t.Type, t.SigningKeyRef = "json", "env:X" }, "autotask targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-6: a syncro target names its API token as a deployment reference and
// at least one meter's product ID; tickets need a problem type, and their
// statuses default to New and Resolved; json, connectwise and autotask
// fields are refused on it, and its block on other types.
func TestProviderBillingSyncSyncroTargetMSP6(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "syncro", Type: "syncro", Endpoint: "https://alpha.syncromsp.com/api/v1",
			Syncro: &SyncroBillingTarget{APITokenRef: "file:/run/secrets/syncro-token", Products: map[string]int64{"agents": 1288302}, // #nosec G101 -- a file: reference to a test-only value (CWE-798)
				Tickets: &SyncroTickets{ProblemType: "Certificates"}}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid syncro target refused: %v", errs)
	}
	if ok.Syncro.Tickets.EffectiveStatusNew() != "New" || ok.Syncro.Tickets.EffectiveStatusClosed() != "Resolved" || len(ok.TicketKinds()) != 4 {
		t.Fatalf("defaults = %q %q %v", ok.Syncro.Tickets.EffectiveStatusNew(), ok.Syncro.Tickets.EffectiveStatusClosed(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":           {func(t *ProviderBillingTarget) { t.Syncro = nil }, ".syncro is required"},
		"bearer":             {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"autotask block":     {func(t *ProviderBillingTarget) { t.Autotask = &AutotaskBillingTarget{} }, "autotask targets only"},
		"inline token":       {func(t *ProviderBillingTarget) { t.Syncro.APITokenRef = "T0KEN" }, ".api_token_ref"},
		"no products":        {func(t *ProviderBillingTarget) { t.Syncro.Products = nil }, ".products must map"},
		"negative product":   {func(t *ProviderBillingTarget) { t.Syncro.Products["agents"] = -1 }, ".products.agents"},
		"no problem type":    {func(t *ProviderBillingTarget) { t.Syncro.Tickets.ProblemType = "" }, ".tickets.problem_type"},
		"same statuses":      {func(t *ProviderBillingTarget) { t.Syncro.Tickets.StatusClosed = "New" }, "must differ"},
		"unknown kind":       {func(t *ProviderBillingTarget) { t.Syncro.Tickets.Kinds = []string{"risk.urgent"} }, "not a ticketed alert kind"},
		"block on autotask":  {func(t *ProviderBillingTarget) { t.Type = "autotask" }, "syncro targets only"},
		"long schedule name": {func(t *ProviderBillingTarget) { t.Syncro.ScheduleName = strings.Repeat("s", 101) }, ".schedule_name"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-5: a halopsa target names the API application's client ID and secret
// reference, an optional hosted tenant, and at least one meter's item ID;
// tickets need a ticket type and a closed status different from the new one;
// json and connectwise fields are refused on it, and its block on other
// types.
func TestProviderBillingSyncHaloPSATargetMSP5(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "halo", Type: "halopsa", Endpoint: "https://alpha.halopsa.com",
			HaloPSA: &HaloPSABillingTarget{Tenant: "alphamsp", ClientID: "trstctl-integration",
				ClientSecretRef: "env:TRSTCTL_HALO_SECRET", Items: map[string]int64{"certificates_current": 901}, // #nosec G101 -- an env: reference to a test-only value (CWE-798)
				Tickets: &HaloPSATickets{TicketTypeID: 21, StatusNewID: 1, StatusClosedID: 9}}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid halopsa target refused: %v", errs)
	}
	if len(ok.TicketKinds()) != 4 {
		t.Fatalf("ticket kinds = %v", ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.HaloPSA = nil }, ".halopsa is required"},
		"signing key":       {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"bad tenant":        {func(t *ProviderBillingTarget) { t.HaloPSA.Tenant = "a b" }, ".tenant"},
		"no client id":      {func(t *ProviderBillingTarget) { t.HaloPSA.ClientID = "" }, ".client_id"},
		"inline secret":     {func(t *ProviderBillingTarget) { t.HaloPSA.ClientSecretRef = "s3cret" }, ".client_secret_ref"},
		"no items":          {func(t *ProviderBillingTarget) { t.HaloPSA.Items = nil }, ".items must map"},
		"zero item":         {func(t *ProviderBillingTarget) { t.HaloPSA.Items["agents"] = 0 }, ".items.agents"},
		"no ticket type":    {func(t *ProviderBillingTarget) { t.HaloPSA.Tickets.TicketTypeID = 0 }, ".tickets.ticket_type_id"},
		"same statuses":     {func(t *ProviderBillingTarget) { t.HaloPSA.Tickets.StatusClosedID = 1 }, ".tickets.status_closed_id"},
		"unknown kind":      {func(t *ProviderBillingTarget) { t.HaloPSA.Tickets.Kinds = []string{"x"} }, "not a ticketed alert kind"},
		"block on syncro":   {func(t *ProviderBillingTarget) { t.Type = "syncro" }, "halopsa targets only"},
		"connectwise block": {func(t *ProviderBillingTarget) { t.ConnectWise = &ConnectWiseBillingTarget{} }, "connectwise targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-7: a gradient target names its GRADIENT-TOKEN reference and at least
// one meter's service ID (path-safe); json and connectwise fields are refused
// on it, and its block on other types; it opens no tickets.
func TestProviderBillingSyncGradientTargetMSP7(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "gradient", Type: "gradient", Endpoint: "https://app.usegradient.com",
			Gradient: &GradientBillingTarget{TokenRef: "env:TRSTCTL_GRADIENT_TOKEN", Services: map[string]string{"agents": "trstctl-agents"}}} // #nosec G101 -- an env: reference to a test-only value (CWE-798)
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid gradient target refused: %v", errs)
	}
	if ok.TicketKinds() != nil {
		t.Fatalf("a gradient target tickets %v", ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.Gradient = nil }, ".gradient is required"},
		"bearer":            {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"inline token":      {func(t *ProviderBillingTarget) { t.Gradient.TokenRef = "abc" }, ".token_ref"},
		"no services":       {func(t *ProviderBillingTarget) { t.Gradient.Services = nil }, ".services must map"},
		"unknown meter":     {func(t *ProviderBillingTarget) { t.Gradient.Services["certificates_issued"] = "x" }, "not a pushed meter"},
		"path in service":   {func(t *ProviderBillingTarget) { t.Gradient.Services["agents"] = "a/../b" }, ".services.agents"},
		"block on halopsa":  {func(t *ProviderBillingTarget) { t.Type = "halopsa" }, "gradient targets only"},
		"connectwise block": {func(t *ProviderBillingTarget) { t.ConnectWise = &ConnectWiseBillingTarget{} }, "connectwise targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-8: a pax8 target names its token URL (https, no credentials), client
// ID and secret reference, and at least one meter's product (a UUID) and
// unit; the audience defaults to Pax8's; json and connectwise fields are
// refused on it, and its block on other types; it opens no tickets.
func TestProviderBillingSyncPax8TargetMSP8(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "pax8", Type: "pax8", Endpoint: "https://api.pax8.com",
			Pax8: &Pax8BillingTarget{TokenURL: "https://login.pax8.com/oauth/token", ClientID: "trstctl-vendor-app",
				ClientSecretRef: "file:/run/secrets/pax8-secret", // #nosec G101 -- a file: reference to a test-only value (CWE-798)
				Products:        map[string]Pax8Product{"agents": {ProductID: "6b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e", UnitOfMeasurement: "Agent"}}}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid pax8 target refused: %v", errs)
	}
	if ok.Pax8.EffectiveAudience() != "api://p8p.client" || ok.TicketKinds() != nil {
		t.Fatalf("audience %q, kinds %v", ok.Pax8.EffectiveAudience(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.Pax8 = nil }, ".pax8 is required"},
		"signing key":       {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"relative token":    {func(t *ProviderBillingTarget) { t.Pax8.TokenURL = "/oauth/token" }, ".token_url"},
		"plain http token":  {func(t *ProviderBillingTarget) { t.Pax8.TokenURL = "http://login.pax8.com/oauth/token" }, ".token_url must use https"},
		"token credentials": {func(t *ProviderBillingTarget) { t.Pax8.TokenURL = "https://a:b@login.pax8.com/oauth/token" }, "must not carry credentials"},
		"no client id":      {func(t *ProviderBillingTarget) { t.Pax8.ClientID = "" }, ".client_id"},
		"inline secret":     {func(t *ProviderBillingTarget) { t.Pax8.ClientSecretRef = "s3cret" }, ".client_secret_ref"},
		"no products":       {func(t *ProviderBillingTarget) { t.Pax8.Products = nil }, ".products must map"},
		"bad product": {func(t *ProviderBillingTarget) {
			t.Pax8.Products["agents"] = Pax8Product{ProductID: "x", UnitOfMeasurement: "Agent"}
		}, ".products.agents"},
		"no unit": {func(t *ProviderBillingTarget) {
			t.Pax8.Products["agents"] = Pax8Product{ProductID: "6b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e"}
		}, ".products.agents"},
		"block on gradient": {func(t *ProviderBillingTarget) { t.Type = "gradient" }, "pax8 targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-9: a ninjaone target names its API client and secret reference and
// the three agent scripts; it is an RMM target that takes no usage and opens
// no tickets; json and connectwise fields are refused on it, and its block on
// other types.
func TestProviderBillingSyncNinjaOneTargetMSP9(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "ninja", Type: "ninjaone", Endpoint: "https://app.ninjarmm.com",
			NinjaOne: &NinjaOneTarget{ClientID: "trstctl-ninja", ClientSecretRef: "file:/run/secrets/ninja-secret", // #nosec G101 -- a file: reference to a test-only value (CWE-798)
				InstallScriptID: 31, UpgradeScriptID: 32, RemoveScriptID: 33, HealthField: "trstctlAgent"}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid ninjaone target refused: %v", errs)
	}
	if !ok.IsRMM() || ok.PushesUsage() || ok.TicketKinds() != nil {
		t.Fatalf("a ninjaone target: rmm=%v usage=%v kinds=%v", ok.IsRMM(), ok.PushesUsage(), ok.TicketKinds())
	}
	if json := (ProviderBillingTarget{Type: "json"}); json.IsRMM() || !json.PushesUsage() {
		t.Fatal("a json target is treated as an RMM")
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.NinjaOne = nil }, ".ninjaone is required"},
		"signing key":       {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"no client id":      {func(t *ProviderBillingTarget) { t.NinjaOne.ClientID = "" }, ".client_id"},
		"inline secret":     {func(t *ProviderBillingTarget) { t.NinjaOne.ClientSecretRef = "s3cret" }, ".client_secret_ref"},
		"no install script": {func(t *ProviderBillingTarget) { t.NinjaOne.InstallScriptID = 0 }, ".install_script_id"},
		"no remove script":  {func(t *ProviderBillingTarget) { t.NinjaOne.RemoveScriptID = -1 }, ".remove_script_id"},
		"bad health field":  {func(t *ProviderBillingTarget) { t.NinjaOne.HealthField = "1st field" }, ".health_field"},
		"block on pax8":     {func(t *ProviderBillingTarget) { t.Type = "pax8" }, "ninjaone targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-10: a datto target is an RMM target with its API key, a file: or env:
// secret reference, three component UIDs and an optional user-defined field
// from 1 to 30.
func TestProviderBillingSyncDattoTargetMSP10(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "datto", Type: "datto", Endpoint: "https://pinotage-api.centrastage.net",
			Datto: &DattoTarget{APIKeyRef: "env:DATTO_API_KEY", APISecretRef: "env:DATTO_API_SECRET", // #nosec G101 -- env: references, not values (CWE-798)
				InstallComponentUID: "c0c0c0c0-0000-4000-8000-0000000000c1", UpgradeComponentUID: "c0c0c0c0-0000-4000-8000-0000000000c2",
				RemoveComponentUID: "c0c0c0c0-0000-4000-8000-0000000000c3", HealthUDF: 12}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid datto target refused: %v", errs)
	}
	if !ok.IsRMM() || ok.PushesUsage() || ok.TicketKinds() != nil {
		t.Fatalf("a datto target: rmm=%v usage=%v kinds=%v", ok.IsRMM(), ok.PushesUsage(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":            {func(t *ProviderBillingTarget) { t.Datto = nil }, ".datto is required"},
		"token ref":           {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"no api key":          {func(t *ProviderBillingTarget) { t.Datto.APIKeyRef = "" }, ".api_key_ref"},
		"inline api key":      {func(t *ProviderBillingTarget) { t.Datto.APIKeyRef = "TRSTCTL-API-KEY" }, ".api_key_ref"},
		"inline secret":       {func(t *ProviderBillingTarget) { t.Datto.APISecretRef = "s3cret" }, ".api_secret_ref"},
		"bad install":         {func(t *ProviderBillingTarget) { t.Datto.InstallComponentUID = "install-me" }, ".install_component_uid"},
		"no remove":           {func(t *ProviderBillingTarget) { t.Datto.RemoveComponentUID = "" }, ".remove_component_uid"},
		"udf out of range":    {func(t *ProviderBillingTarget) { t.Datto.HealthUDF = 31 }, ".health_udf"},
		"block on ninjaone":   {func(t *ProviderBillingTarget) { t.Type = "ninjaone" }, "datto targets only"},
		"negative udf":        {func(t *ProviderBillingTarget) { t.Datto.HealthUDF = -1 }, ".health_udf"},
		"component not a UID": {func(t *ProviderBillingTarget) { t.Datto.UpgradeComponentUID = "c0c0c0c0" }, ".upgrade_component_uid"},
		"id too long":         {func(t *ProviderBillingTarget) { t.ID = strings.Repeat("d", 24) }, "at most 23 characters"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-12: an ncentral target is an RMM target with the API user's JWT
// reference, three script IDs, an optional credential type and an optional
// health custom property.
func TestProviderBillingSyncNCentralTargetMSP12(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "ncentral", Type: "ncentral", Endpoint: "https://ncentral.example.com",
			NCentral: &NCentralTarget{UserJWTRef: "file:/run/secrets/ncentral-jwt", // #nosec G101 -- a file: reference, not a value (CWE-798)
				InstallScriptID: 701, UpgradeScriptID: 702, RemoveScriptID: 703, HealthPropertyID: 88}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid ncentral target refused: %v", errs)
	}
	if !ok.IsRMM() || ok.PushesUsage() || ok.TicketKinds() != nil {
		t.Fatalf("an ncentral target: rmm=%v usage=%v kinds=%v", ok.IsRMM(), ok.PushesUsage(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.NCentral = nil }, ".ncentral is required"},
		"signing key":       {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"inline jwt":        {func(t *ProviderBillingTarget) { t.NCentral.UserJWTRef = "eyJ.x.y" }, ".user_jwt_ref"},
		"no install script": {func(t *ProviderBillingTarget) { t.NCentral.InstallScriptID = 0 }, ".install_script_id"},
		"no upgrade script": {func(t *ProviderBillingTarget) { t.NCentral.UpgradeScriptID = -2 }, ".upgrade_script_id"},
		"bad credential":    {func(t *ProviderBillingTarget) { t.NCentral.CredentialType = "line\nbreak" }, ".credential_type"},
		"negative property": {func(t *ProviderBillingTarget) { t.NCentral.HealthPropertyID = -1 }, ".health_property_id"},
		"block on datto":    {func(t *ProviderBillingTarget) { t.Type = "datto" }, "ncentral targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-13: a kaseya target is an RMM target with the VSA user, a personal
// access token reference, three procedure IDs, the enrollment custom field
// and an optional, different health custom field.
func TestProviderBillingSyncKaseyaTargetMSP13(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "vsa", Type: "kaseya", Endpoint: "https://vsa.example.com",
			Kaseya: &KaseyaTarget{Username: "trstctl-integration", AccessTokenRef: "env:VSA_PAT", // #nosec G101 -- an env: reference, not a value (CWE-798)
				InstallProcedureID: 41, UpgradeProcedureID: 42, RemoveProcedureID: 43, EnrollmentField: "trstctlEnrollment", HealthField: "trstctlAgent"}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid kaseya target refused: %v", errs)
	}
	if !ok.IsRMM() || ok.PushesUsage() || ok.TicketKinds() != nil {
		t.Fatalf("a kaseya target: rmm=%v usage=%v kinds=%v", ok.IsRMM(), ok.PushesUsage(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":            {func(t *ProviderBillingTarget) { t.Kaseya = nil }, ".kaseya is required"},
		"token ref":           {func(t *ProviderBillingTarget) { t.TokenRef = "env:X" }, "json targets only"},
		"colon in user":       {func(t *ProviderBillingTarget) { t.Kaseya.Username = "a:b" }, ".username"},
		"inline token":        {func(t *ProviderBillingTarget) { t.Kaseya.AccessTokenRef = "pat-value" }, ".access_token_ref"},
		"no remove procedure": {func(t *ProviderBillingTarget) { t.Kaseya.RemoveProcedureID = 0 }, ".remove_procedure_id"},
		"no enrollment field": {func(t *ProviderBillingTarget) { t.Kaseya.EnrollmentField = "" }, ".enrollment_field"},
		"same health field":   {func(t *ProviderBillingTarget) { t.Kaseya.HealthField = "trstctlEnrollment" }, ".health_field"},
		"block on ncentral":   {func(t *ProviderBillingTarget) { t.Type = "ncentral" }, "kaseya targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}

// MSP-11: an automate target is an RMM target with the integrator user, a
// password reference, the integration's client ID, the execute command and
// three shell lines.
func TestProviderBillingSyncAutomateTargetMSP11(t *testing.T) {
	valid := func() ProviderBillingTarget {
		return ProviderBillingTarget{ID: "automate", Type: "automate", Endpoint: "https://automate.example.com",
			Automate: &AutomateTarget{Username: "trstctl-integrator", PasswordRef: "env:AUTOMATE_PASSWORD", // #nosec G101 -- an env: reference, not a value (CWE-798)
				ClientID: "0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f", ExecuteCommandID: 2, InstallLine: `powershell.exe!!! -File C:\trstctl\install.ps1`,
				UpgradeLine: `powershell.exe!!! -File C:\trstctl\upgrade.ps1`, RemoveLine: `cmd.exe!!! /c C:\trstctl\remove.cmd`}}
	}
	ok := valid()
	if errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{ok}}); len(errs) != 0 {
		t.Fatalf("valid automate target refused: %v", errs)
	}
	if !ok.IsRMM() || ok.PushesUsage() || ok.TicketKinds() != nil {
		t.Fatalf("an automate target: rmm=%v usage=%v kinds=%v", ok.IsRMM(), ok.PushesUsage(), ok.TicketKinds())
	}
	for name, tc := range map[string]struct {
		mutate func(*ProviderBillingTarget)
		want   string
	}{
		"no block":          {func(t *ProviderBillingTarget) { t.Automate = nil }, ".automate is required"},
		"signing key":       {func(t *ProviderBillingTarget) { t.SigningKeyRef = "env:X" }, "json targets only"},
		"no user":           {func(t *ProviderBillingTarget) { t.Automate.Username = "" }, ".username"},
		"inline password":   {func(t *ProviderBillingTarget) { t.Automate.PasswordRef = "hunter2" }, ".password_ref"},
		"client id":         {func(t *ProviderBillingTarget) { t.Automate.ClientID = "trstctl" }, ".client_id"},
		"no command":        {func(t *ProviderBillingTarget) { t.Automate.ExecuteCommandID = 0 }, ".execute_command_id"},
		"no shell marker":   {func(t *ProviderBillingTarget) { t.Automate.InstallLine = `C:\trstctl\install.ps1` }, ".install_line"},
		"control character": {func(t *ProviderBillingTarget) { t.Automate.RemoveLine = "cmd.exe!!! /c a\nb" }, ".remove_line"},
		"block on kaseya":   {func(t *ProviderBillingTarget) { t.Type = "kaseya" }, "automate targets only"},
	} {
		target := valid()
		tc.mutate(&target)
		errs := validateProviderBillingSync(ProviderBillingSync{Targets: []ProviderBillingTarget{target}})
		joined := ""
		for _, err := range errs {
			joined += err.Error() + "\n"
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: errors %q, want one naming %q", name, joined, tc.want)
		}
	}
}
