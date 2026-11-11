// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/mdm"
)

const (
	jamfAPIClientID  = "00000000-0000-4000-8000-00000000a15c"
	jamfSecretRef    = "secret://mdm/jamf/api-client-secret" // #nosec G101 -- credential reference, no credential value present (CWE-798)
	jamfClientSecret = "stand-in jamf client secret"         // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	jamfExchanged    = "jamf-token-from-exchange"
)

// jamfAPIStandIn is a Jamf Pro server from Jamf's documented API: the API
// client token endpoint, the computers-inventory read and the Classic API
// blank push, each of the last two answering only the exchanged bearer.
func jamfAPIStandIn(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/oauth/token":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != jamfAPIClientID ||
				r.PostForm.Get("client_secret") != jamfClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + jamfExchanged + `","scope":"api-role:2","token_type":"Bearer","expires_in":299}`))
		case r.Header.Get("Authorization") != "Bearer "+jamfExchanged:
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/computers-inventory":
			_, _ = w.Write([]byte(`{"results":[{"id":"7","general":{"name":"mac-1"},"hardware":{"serialNumber":"C02XYZ"}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/JSSResource/computercommands/command/BlankPush/id/417":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}
}

// A156-L1: a Jamf read whose schedule names a Jamf Pro API client exchanges
// the redeemed client secret at the same server and reads the inventory with
// the access token it gets; a refused secret is named as Jamf's refusal and
// never reaches the inventory.
func TestRelayMDMSyncExchangesTheJamfAPIClientSecretA156L1(t *testing.T) {
	srv, calls := jamfAPIStandIn(t)
	intent := mdm.SyncIntent{MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: jamfSecretRef,
		JamfAPIClient: &mdm.JamfAPIClient{ClientID: jamfAPIClientID}}
	ch := &fakeChannel{jobs: []relay.Job{mdmJob(t, intent)}, material: map[string][]byte{jamfSecretRef: []byte(jamfClientSecret)}}
	executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30)
	if err != nil || executed != 1 {
		t.Fatalf("executed = %d, %v; reports %+v; calls %v", executed, err, ch.reports, calls())
	}
	var report struct {
		Devices []mdm.Device `json:"devices"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || len(report.Devices) != 1 || report.Devices[0].SerialNumber != "C02XYZ" {
		t.Fatalf("report = %q; want the inventory read with the exchanged token", ch.reports[0].detail)
	}
	if got := calls(); len(got) != 2 || got[0] != "POST /api/oauth/token" || got[1] != "GET /api/v1/computers-inventory" {
		t.Fatalf("calls = %v; want one exchange, then one read", got)
	}

	refused := &fakeChannel{jobs: []relay.Job{mdmJob(t, intent)}, material: map[string][]byte{jamfSecretRef: []byte("wrong secret")}}
	if executed, _ := relay.RunOnce(t.Context(), refused, srv.Client(), 4, 30); executed != 0 || len(refused.reports) != 1 {
		t.Fatalf("a refused secret executed = %d; reports %+v", executed, refused.reports)
	}
	if detail := refused.reports[0].detail; detail != "Jamf Pro refused the API client ID or client secret" || strings.Contains(detail, "wrong secret") {
		t.Fatalf("refusal detail = %q", detail)
	}
	if got := calls(); len(got) != 3 || got[2] != "POST /api/oauth/token" {
		t.Fatalf("calls after a refused secret = %v; want no read", got)
	}

	intune := mdm.SyncIntent{MDM: mdm.MDMIntune, BaseURL: srv.URL, TokenRef: jamfSecretRef, JamfAPIClient: &mdm.JamfAPIClient{ClientID: jamfAPIClientID}}
	wrong := &fakeChannel{jobs: []relay.Job{mdmJob(t, intune)}, material: map[string][]byte{jamfSecretRef: []byte(jamfClientSecret)}}
	if executed, _ := relay.RunOnce(t.Context(), wrong, srv.Client(), 4, 30); executed != 0 || len(wrong.reports) != 1 ||
		wrong.reports[0].detail != "a Jamf Pro API client is only valid for a Jamf read" {
		t.Fatalf("a Jamf API client on an Intune read = %d; reports %+v", executed, wrong.reports)
	}
}

// A156-L1: a Jamf check-in through an API client exchanges the secret the
// same way and pushes with the access token; one naming an API client on
// Intune, or a malformed client ID, is refused before anything is redeemed.
func TestRelayMDMCheckInExchangesTheJamfAPIClientSecretA156L1(t *testing.T) {
	srv, calls := jamfAPIStandIn(t)
	intent := relay.MDMCheckInIntent{ID: "check-in-jamf-client", MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: jamfSecretRef,
		JamfAPIClient: &mdm.JamfAPIClient{ClientID: jamfAPIClientID}, DeviceID: "417", RequiredAgentID: "agent-1"}
	ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{jamfSecretRef: []byte(jamfClientSecret)}}
	if executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 1, 60); err != nil || executed != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
		t.Fatalf("executed = %d, %v; reports %+v; calls %v", executed, err, ch.reports, calls())
	}
	if got := calls(); len(got) != 2 || got[0] != "POST /api/oauth/token" || got[1] != "POST /JSSResource/computercommands/command/BlankPush/id/417" {
		t.Fatalf("calls = %v; want one exchange, then one blank push", got)
	}
	for name, bad := range map[string]relay.MDMCheckInIntent{
		"intune": {ID: "c1", MDM: mdm.MDMIntune, BaseURL: srv.URL, TokenRef: jamfSecretRef, JamfAPIClient: &mdm.JamfAPIClient{ClientID: jamfAPIClientID},
			DeviceID: "0f7c2a4e-3b1d-4e5f-9a8b-7c6d5e4f3a2b", RequiredAgentID: "agent-1"},
		"malformed id": {ID: "c2", MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: jamfSecretRef, JamfAPIClient: &mdm.JamfAPIClient{ClientID: "client"},
			DeviceID: "417", RequiredAgentID: "agent-1"},
	} {
		refused := &fakeChannel{jobs: []relay.Job{checkInJob(t, bad)}, material: map[string][]byte{jamfSecretRef: []byte(jamfClientSecret)}}
		if _, err := relay.RunOnce(t.Context(), refused, srv.Client(), 1, 60); err != nil {
			t.Fatal(err)
		}
		if refused.redeemed != 0 || len(refused.reports) != 1 || refused.reports[0].outcome != transport.JobOutcomeFailed {
			t.Fatalf("%s: redeemed %d; reports %+v", name, refused.redeemed, refused.reports)
		}
	}
	if got := calls(); len(got) != 2 {
		t.Fatalf("a refused check-in reached Jamf: %v", got)
	}
}
