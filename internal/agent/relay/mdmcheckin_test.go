// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/mdm"
)

// N9: the relay half of an MDM device check-in. One bodiless POST to a fixed
// endpoint — Graph's syncDevice or a Jamf blank push to one computer — with
// the token redeemed for this attempt, and a report only of what the MDM
// answered.

const checkInTokenRef = "secret://n9-mdm-token" // #nosec G101 -- credential reference (secret store pointer), no credential value present (CWE-798)

type checkInCall struct {
	method, path, authorization string
	body                        int
}

// checkInMDM is a stand-in MDM that answers every call with status and
// records what it was asked.
func checkInMDM(t *testing.T, status int) (*httptest.Server, func() []checkInCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []checkInCall
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, checkInCall{method: r.Method, path: r.URL.Path, authorization: r.Header.Get("Authorization"), body: len(body)})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []checkInCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]checkInCall(nil), calls...)
	}
}

func checkInJob(t *testing.T, intent relay.MDMCheckInIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 9, Kind: relay.KindMDMCheckIn, Attempt: 1, Payload: payload}
}

func TestRelayMDMCheckInPostsOnceToTheFixedEndpointN9(t *testing.T) {
	for _, tc := range []struct {
		provider, device, path string
		status                 int
	}{
		{mdm.MDMIntune, "0f7c2a4e-3b1d-4e5f-9a8b-7c6d5e4f3a2b", "/v1.0/deviceManagement/managedDevices/0f7c2a4e-3b1d-4e5f-9a8b-7c6d5e4f3a2b/syncDevice", http.StatusNoContent},
		{mdm.MDMJamf, "417", "/JSSResource/computercommands/command/BlankPush/id/417", http.StatusCreated},
	} {
		srv, calls := checkInMDM(t, tc.status)
		intent := relay.MDMCheckInIntent{ID: "check-in-1", MDM: tc.provider, BaseURL: srv.URL + "/", TokenRef: checkInTokenRef,
			DeviceID: tc.device, RequiredAgentID: "agent-1"}
		ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{checkInTokenRef: []byte("mdm-test-token")}}
		executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 1, 60)
		if err != nil || executed != 1 || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted {
			t.Fatalf("%s: executed = %d, %v; reports %+v", tc.provider, executed, err, ch.reports)
		}
		got := calls()
		if len(got) != 1 || got[0].method != http.MethodPost || got[0].path != tc.path || got[0].authorization != "Bearer mdm-test-token" || got[0].body != 0 {
			t.Fatalf("%s: MDM calls = %+v", tc.provider, got)
		}
		var report relay.MDMCheckInReport
		if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
			t.Fatal(err)
		}
		if report.ProviderStatus != tc.status || relay.ValidateMDMCheckInReport(intent, report) != nil {
			t.Fatalf("%s: report = %+v", tc.provider, report)
		}
	}
}

func TestRelayMDMCheckInReportsTheMDMRefusalN9(t *testing.T) {
	srv, calls := checkInMDM(t, http.StatusNotFound)
	intent := relay.MDMCheckInIntent{ID: "check-in-2", MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: checkInTokenRef,
		DeviceID: "999", RequiredAgentID: "agent-1"}
	ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{checkInTokenRef: []byte("mdm-test-token")}}
	if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 1, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed || !strings.Contains(ch.reports[0].detail, "status 404") || len(calls()) != 1 {
		t.Fatalf("refused check-in reports %+v after %d calls", ch.reports, len(calls()))
	}
}

func TestRelayMDMCheckInRefusesBeforeRedeemingN9(t *testing.T) {
	base := relay.MDMCheckInIntent{ID: "check-in-3", MDM: mdm.MDMIntune, BaseURL: "https://graph.example.test", TokenRef: checkInTokenRef,
		DeviceID: "dev-1", RequiredAgentID: "agent-1"}
	for name, mutate := range map[string]func(*relay.MDMCheckInIntent){
		"plain http":                  func(i *relay.MDMCheckInIntent) { i.BaseURL = "http://graph.example.test" },
		"query on the base":           func(i *relay.MDMCheckInIntent) { i.BaseURL = "https://graph.example.test/?x=1" },
		"another MDM":                 func(i *relay.MDMCheckInIntent) { i.MDM = "workspace-one" },
		"a path in the device":        func(i *relay.MDMCheckInIntent) { i.DeviceID = "dev-1/wipe" },
		"a Jamf device that is no id": func(i *relay.MDMCheckInIntent) { i.MDM, i.DeviceID = mdm.MDMJamf, "computer-7" },
		"client credentials for Jamf": func(i *relay.MDMCheckInIntent) {
			i.MDM, i.DeviceID, i.ClientCredentials = mdm.MDMJamf, "7", &mdm.ClientCredentials{ClientID: "x"}
		},
		"no exact relay":     func(i *relay.MDMCheckInIntent) { i.RequiredAgentID = "" },
		"no token reference": func(i *relay.MDMCheckInIntent) { i.TokenRef = "" },
	} {
		intent := base
		mutate(&intent)
		if relay.ValidateMDMCheckInIntent(intent) == nil {
			t.Fatalf("%s: intent accepted", name)
		}
		ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{checkInTokenRef: []byte("mdm-test-token")}}
		if _, err := relay.RunOnce(t.Context(), ch, http.DefaultClient, 1, 60); err != nil {
			t.Fatal(err)
		}
		if ch.redeemed != 0 || len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed {
			t.Fatalf("%s: redeemed %d, reports %+v", name, ch.redeemed, ch.reports)
		}
	}
	if relay.ValidateMDMCheckInIntent(base) != nil {
		t.Fatal("the base intent is valid")
	}
	if err := relay.ValidateMDMCheckInReport(base, relay.MDMCheckInReport{MDM: mdm.MDMIntune, DeviceID: "dev-2", ProviderStatus: 204}); err == nil {
		t.Fatal("a report naming another device was accepted")
	}
	if err := relay.ValidateMDMCheckInReport(base, relay.MDMCheckInReport{MDM: mdm.MDMIntune, DeviceID: "dev-1", ProviderStatus: 404}); err == nil {
		t.Fatal("a report of a refused check-in was accepted")
	}
}
