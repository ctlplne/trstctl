// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

// mdmAnswer is one answer of a sequenced stand-in MDM.
type mdmAnswer struct {
	status     int
	retryAfter string
}

// checkInMDMSequence answers the calls in order (the last answer repeats).
func checkInMDMSequence(t *testing.T, answers ...mdmAnswer) (*httptest.Server, func() []checkInCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []checkInCall
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, checkInCall{method: r.Method, path: r.URL.Path, authorization: r.Header.Get("Authorization")})
		answer := answers[min(len(calls), len(answers))-1]
		mu.Unlock()
		if answer.retryAfter != "" {
			w.Header().Set("Retry-After", answer.retryAfter)
		}
		w.WriteHeader(answer.status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []checkInCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]checkInCall(nil), calls...)
	}
}

// recordWaits replaces the wait between attempts with a recorder.
func recordWaits(t *testing.T) func() []time.Duration {
	t.Helper()
	var waits []time.Duration
	previous := relay.MDMCheckInWait
	relay.MDMCheckInWait = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	t.Cleanup(func() { relay.MDMCheckInWait = previous })
	return func() []time.Duration { return waits }
}

// TestRelayMDMCheckInRetriesThrottlingUnderTheSameApprovalN9L3 is N9-L3: an
// MDM that answers 429 (with Retry-After) and then 503 is asked again in the
// same job with the same token, and its 204 is the check-in's result.
func TestRelayMDMCheckInRetriesThrottlingUnderTheSameApprovalN9L3(t *testing.T) {
	waits := recordWaits(t)
	srv, calls := checkInMDMSequence(t, mdmAnswer{status: http.StatusTooManyRequests, retryAfter: "7"}, mdmAnswer{status: http.StatusServiceUnavailable},
		mdmAnswer{status: http.StatusNoContent})
	intent := relay.MDMCheckInIntent{ID: "check-in-l3", MDM: mdm.MDMIntune, BaseURL: srv.URL, TokenRef: checkInTokenRef,
		DeviceID: "0f7c2a4e-3b1d-4e5f-9a8b-7c6d5e4f3a2b", RequiredAgentID: "agent-1"}
	ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{checkInTokenRef: []byte("mdm-test-token")}}
	if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 1, 120); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeExecuted || ch.redeemed != 1 {
		t.Fatalf("reports %+v after %d redemptions", ch.reports, ch.redeemed)
	}
	var report relay.MDMCheckInReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || report.ProviderStatus != http.StatusNoContent {
		t.Fatalf("report = %+v, %v", report, err)
	}
	got := calls()
	if len(got) != 3 {
		t.Fatalf("MDM calls = %d, want 3", len(got))
	}
	for _, call := range got {
		if call.authorization != "Bearer mdm-test-token" || call.method != http.MethodPost {
			t.Fatalf("a retry did not carry the same token: %+v", got)
		}
	}
	if w := waits(); len(w) != 2 || w[0] != 7*time.Second || w[1] != 4*time.Second {
		t.Fatalf("waits = %v; want the MDM's 7s, then 4s", w)
	}
}

// TestRelayMDMCheckInGivesUpWithinItsBoundsN9L3: an MDM that keeps failing is
// asked at most four times; waits the MDM asks for are capped at 30 seconds
// and stop once a minute of them would pass; a refusal that is not 429 or 5xx
// is not retried.
func TestRelayMDMCheckInGivesUpWithinItsBoundsN9L3(t *testing.T) {
	run := func(answers ...mdmAnswer) (string, int, []time.Duration) {
		t.Helper()
		waits := recordWaits(t)
		srv, calls := checkInMDMSequence(t, answers...)
		intent := relay.MDMCheckInIntent{ID: "check-in-l3b", MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: checkInTokenRef,
			DeviceID: "417", RequiredAgentID: "agent-1"}
		ch := &fakeChannel{jobs: []relay.Job{checkInJob(t, intent)}, material: map[string][]byte{checkInTokenRef: []byte("mdm-test-token")}}
		if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 1, 120); err != nil {
			t.Fatal(err)
		}
		if len(ch.reports) != 1 || ch.reports[0].outcome != transport.JobOutcomeFailed {
			t.Fatalf("reports = %+v", ch.reports)
		}
		return ch.reports[0].detail, len(calls()), waits()
	}
	if detail, n, w := run(mdmAnswer{status: http.StatusServiceUnavailable}); n != 4 || !strings.Contains(detail, "status 503 after 4 attempts") ||
		len(w) != 3 || w[0] != 2*time.Second || w[1] != 4*time.Second || w[2] != 8*time.Second {
		t.Fatalf("an MDM that keeps failing: %q after %d calls, waits %v", detail, n, w)
	}
	if detail, n, w := run(mdmAnswer{status: http.StatusTooManyRequests, retryAfter: "3600"}); n != 3 || !strings.Contains(detail, "status 429 after 3 attempts") ||
		len(w) != 2 || w[0] != 30*time.Second || w[1] != 30*time.Second {
		t.Fatalf("an MDM asking for an hour: %q after %d calls, waits %v", detail, n, w)
	}
	if detail, n, w := run(mdmAnswer{status: http.StatusForbidden}); n != 1 || strings.Contains(detail, "attempts") || len(w) != 0 {
		t.Fatalf("a 403: %q after %d calls, waits %v", detail, n, w)
	}
}
