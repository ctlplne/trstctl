// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestDependentProbeIsLocalFreshAndCannotFollowRedirectsA267(t *testing.T) {
	var challenge string
	var foreign int
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign++; w.WriteHeader(200) }))
	defer forbidden.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge = r.URL.Query().Get("challenge")
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, forbidden.URL, http.StatusFound)
			return
		}
		value := servicedependents.FunctionalProof{ProbeID: "owned", Challenge: challenge, AccountSID: "S-1-5-21-1-2-3-1001", ProcessID: 42, EvidenceSHA256: strings.Repeat("a", 64)}
		if r.URL.Path == "/stale" {
			value.Challenge = "66666666-6666-4666-8666-666666666666"
		}
		_ = json.NewEncoder(w).Encode(value)
	}))
	defer upstream.Close()
	step := servicedependents.RotationStep{ProbeID: "owned", AccountSID: "S-1-5-21-1-2-3-1001", Challenge: "55555555-5555-4555-8555-555555555555", NotBefore: time.Now().UTC(), Deadline: time.Now().UTC().Add(time.Minute)}
	good := connector.WindowsDependentProbe{ID: "owned", URL: upstream.URL + "/work"}
	proof, e := runDependentFunctionalProbe(t.Context(), good, step, "")
	if e != nil || proof.Challenge != step.Challenge || challenge != step.Challenge {
		t.Fatal("fresh local work failed", e)
	}
	for _, path := range []string{"/redirect", "/stale"} {
		altered := good
		altered.URL = upstream.URL + path
		if _, e := runDependentFunctionalProbe(t.Context(), altered, step, ""); e == nil {
			t.Fatal("redirect/stale work was accepted", path)
		}
	}
	if foreign != 0 {
		t.Fatal("functional probe followed a redirect")
	}
	for _, address := range []string{"http://169.254.169.254/work", "http://example.test/work", "http://127.0.0.1/work?arbitrary=true", "http://user@127.0.0.1:8080/work", "file:///owned"} {
		if validateDependentProbe(connector.WindowsDependentProbe{ID: "owned", URL: address}) == nil {
			t.Fatal("unbounded/nonlocal probe destination accepted", address)
		}
	}
}
