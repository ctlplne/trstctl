// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

type catalogBody struct {
	Items []struct {
		Name         string   `json:"name"`
		Native       bool     `json:"native"`
		Capabilities []string `json:"capabilities"`
		ReplaySafety string   `json:"replay_safety"`
	} `json:"items"`
}

// AUD-33 served proof: the authenticated HTTP route publishes the source
// plan's denominator, not only the connector subset the relay binary currently
// advertises. The three counts make retained paths visibly open and keep all
// six omitted families in the operator-facing migration program.
func TestServedConnectorCatalogPublishesAllE1Dispositions(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/catalog", nil)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []struct {
			Name        string `json:"name"`
			RelayParity *struct {
				Disposition string `json:"disposition"`
			} `json:"relay_parity"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a10", "aws-acm", "azure-keyvault", "cisco", "envoy", "f5", "fortigate",
		"gcp-certificate-manager", "kemp", "mysql", "netscaler", "paloalto", "postgresql",
	}
	got := make([]string, 0, len(want))
	counts := map[string]int{}
	for _, item := range body.Items {
		if item.RelayParity == nil {
			continue
		}
		got = append(got, item.Name)
		counts[item.RelayParity.Disposition]++
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("served E1 families = %v, want %v", got, want)
	}
	// A59: GCP Certificate Manager migrated; ACM and Key Vault are retained
	// exceptions; Envoy, PostgreSQL and MySQL remain host work. A122: cisco
	// migrated once an ISE target became re-bindable and readable.
	if counts["migrated"] != 8 || counts["architecture_exception"] != 2 || counts["unimplemented"] != 3 || len(counts) != 3 {
		t.Fatalf("served E1 dispositions = %v", counts)
	}
}

// fakeConnector declares a grant without doing any work, so the catalog test
// never runs connector code to report on it.
type fakeConnector struct {
	name string
	caps pluginhost.Grant
}

func (f fakeConnector) Name() string                   { return f.name }
func (f fakeConnector) Capabilities() pluginhost.Grant { return f.caps }
func (f fakeConnector) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	return nil
}

func fetchCatalog(t *testing.T, handler http.Handler) catalogBody {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/catalog", nil)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body catalogBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func catalogItem(t *testing.T, body catalogBody, name string) struct {
	Name         string   `json:"name"`
	Native       bool     `json:"native"`
	Capabilities []string `json:"capabilities"`
	ReplaySafety string   `json:"replay_safety"`
} {
	t.Helper()
	for _, item := range body.Items {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("catalog has no %q row", name)
	return body.Items[0]
}

// B-6: the catalog said what a connector deploys, never what it is permitted
// to do or how it behaves on a redelivery. These pin that the sandbox facts
// come from the live registry, so the catalog cannot claim a capability the
// process would not enforce.
func TestConnectorCatalogReportsRegistrySandboxFacts(t *testing.T) {
	registry := connector.NewRegistry()
	registry.RegisterWithReplaySafety(
		fakeConnector{name: "nginx", caps: pluginhost.NewGrant(pluginhost.CapFSWrite, pluginhost.CapFSRead, connector.CapExec)},
		connector.ReplaySafetyReconciled,
	)
	registry.Register(fakeConnector{name: "haproxy", caps: pluginhost.NewGrant(pluginhost.CapFSWrite)})

	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithConnectorRegistry(registry))
	body := fetchCatalog(t, handler)

	nginx := catalogItem(t, body, "nginx")
	if !nginx.Native {
		t.Fatal("nginx should report native with a registry entry")
	}
	// Sorted, so the console renders a stable list.
	if len(nginx.Capabilities) != 3 || nginx.Capabilities[0] != "fs.read" || nginx.Capabilities[1] != "fs.write" || nginx.Capabilities[2] != "process.exec" {
		t.Fatalf("nginx capabilities = %v, want sorted fs.read/fs.write/process.exec", nginx.Capabilities)
	}
	if nginx.ReplaySafety != "reconciled" {
		t.Fatalf("nginx replay_safety = %q, want reconciled", nginx.ReplaySafety)
	}

	// Register() without an explicit contract must stay conservative.
	haproxy := catalogItem(t, body, "haproxy")
	if haproxy.ReplaySafety != "at-most-once" {
		t.Fatalf("haproxy replay_safety = %q, want the conservative default", haproxy.ReplaySafety)
	}

	// A described connector this build does not implement natively must not
	// claim to be native or to hold capabilities.
	unregistered := catalogItem(t, body, "f5")
	if unregistered.Native || len(unregistered.Capabilities) != 0 {
		t.Fatalf("unregistered connector = %+v, want native=false with no capabilities", unregistered)
	}
	if unregistered.ReplaySafety != "at-most-once" {
		t.Fatalf("unregistered replay_safety = %q, want at-most-once", unregistered.ReplaySafety)
	}
}

// Without a registry the catalog still answers, and answers conservatively:
// nothing is native, nothing holds a capability, everything is at-most-once.
func TestConnectorCatalogWithoutRegistryClaimsNothing(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	body := fetchCatalog(t, handler)

	if len(body.Items) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, item := range body.Items {
		if item.Native || len(item.Capabilities) != 0 || item.ReplaySafety != "at-most-once" {
			t.Fatalf("row %+v claims a sandbox fact with no registry wired", item)
		}
	}
}

// A74/A75: a factory-registered family reports the grant its composition
// declared, a family this process does not run reports the shipped census's
// grant with its executor named, and a control-plane family nothing enabled
// says so instead of reading as a native connector.
func TestConnectorCatalogNamesTheExecutorAndTheDeclaredGrant(t *testing.T) {
	registry := connector.NewRegistry()
	if err := registry.RegisterFactory("f5", func(context.Context, connector.DeployPayload) (connector.Connector, connector.Ops, func(), error) {
		t.Fatal("the catalog constructed a connector to report on it")
		return nil, nil, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.DeclareCapabilities("f5", pluginhost.NewGrant(pluginhost.CapNetDial)); err != nil {
		t.Fatal(err)
	}
	if err := registry.DeclareTargetVantage("f5", connector.VantageNetworkRelay); err != nil {
		t.Fatal(err)
	}
	census := func(name string) []string {
		switch name {
		case "nginx":
			return []string{"fs.write", "process.exec"}
		case "aws-acm":
			return []string{"net.dial"}
		}
		return nil
	}
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithConnectorRegistry(registry), api.WithConnectorGrantCensus(census))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/catalog", nil)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []struct {
			Name         string   `json:"name"`
			Native       bool     `json:"native"`
			Capabilities []string `json:"capabilities"`
			GrantSource  string   `json:"grant_source"`
			Executor     string   `json:"executor"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	rows := map[string]struct {
		Native       bool
		Capabilities []string
		GrantSource  string
		Executor     string
	}{}
	for _, item := range body.Items {
		rows[item.Name] = struct {
			Native       bool
			Capabilities []string
			GrantSource  string
			Executor     string
		}{item.Native, item.Capabilities, item.GrantSource, item.Executor}
	}
	if f5 := rows["f5"]; !f5.Native || f5.GrantSource != "registry" || !reflect.DeepEqual(f5.Capabilities, []string{"net.dial"}) || f5.Executor != "network_relay" {
		t.Fatalf("factory-registered f5 = %+v, want its declared net.dial grant from the registry on a network relay", f5)
	}
	if nginx := rows["nginx"]; nginx.Native || nginx.GrantSource != "shipped" || !reflect.DeepEqual(nginx.Capabilities, []string{"fs.write", "process.exec"}) || nginx.Executor != "host_agent" {
		t.Fatalf("nginx the control plane never enabled = %+v, want the shipped grant and the host agent as executor", nginx)
	}
	// A cloud store nothing enabled here is still executed by an enrolled
	// relay (A59); its shipped grant is named beside that executor.
	if acm := rows["aws-acm"]; acm.Native || acm.Executor != "network_relay" || acm.GrantSource != "shipped" {
		t.Fatalf("aws-acm nothing enabled = %+v, want the relay as executor with its shipped grant", acm)
	}
}
