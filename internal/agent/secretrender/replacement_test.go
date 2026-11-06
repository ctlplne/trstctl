// SPDX-License-Identifier: BUSL-1.1
package secretrender

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type replacementSource struct {
	publication ReplacementPublication
	version     int
	value       []byte
	reads       int
}

func (s *replacementSource) ReadReplacement(context.Context, string) (ReplacementPublication, error) {
	s.reads++
	return s.publication, nil
}
func (s *replacementSource) Fetch(context.Context, string) ([]byte, int, error) {
	return bytes.Clone(s.value), s.version, nil
}

type replacementReports struct{ verified []map[string]int }

func (s *replacementReports) Report(_ context.Context, _, state string, v map[string]int) error {
	if state == "verified" {
		cp := map[string]int{}
		for k, n := range v {
			cp[k] = n
		}
		s.verified = append(s.verified, cp)
	}
	return nil
}

func TestReplacementRendererAdoptsExactPublicationBeforeIndependentIssueA264(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	file := filepath.Join(dir, "credential.json")
	source := &replacementSource{publication: ReplacementPublication{ID: "11111111-1111-4111-8111-111111111111", State: "awaiting_approval", Action: "replace_key", Consumer: "orders", Provider: "sts", Role: "orders", LeaseID: "approved-L1", NativeRoleID: "AROAEXACT", Version: 2, ExpectedVersion: 1, ExpiresAt: now.Add(15 * time.Minute)}, version: 2, value: []byte(`{"access_key_id":"owned-L1","expiration":"` + now.Add(15*time.Minute).Format(time.RFC3339) + `"}`)}
	defer secret.Wipe(source.value)
	leases := &fakeLeases{clock: &now, byKey: map[string]Lease{}, revoked: map[string]bool{}, noRenew: true}
	reports := &replacementReports{}
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		v, err := os.ReadFile(file) // #nosec G304 -- this test reads only its own temporary renderer destination (CWE-22)
		defer secret.Wipe(v)
		if err != nil || len(v) == 0 {
			w.WriteHeader(503)
		}
	}))
	defer probe.Close()
	cfg := Config{Server: "unused", TokenFile: "unused", Consumer: "orders", StateDir: filepath.Join(dir, "state"), Templates: []Template{{Name: "orders", Destination: file, LeaseTTL: 15 * time.Minute, Text: `{{ lease "sts/orders" }}`, Verify: Verify{URL: probe.URL}, Replacement: &ReplacementBootstrap{ChangeID: source.publication.ID, Provider: "sts", Role: "orders"}}}}
	r, err := New(cfg, source, reports, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(leases)
	r.now = func() time.Time { return now }
	r.Once(t.Context())
	if leases.n != 0 {
		t.Fatal("independent session minted before approved publication")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("unapproved publication rendered")
	}
	source.publication.State = "waiting_adoption"
	source.version = 3
	r.Once(t.Context())
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("different secret version rendered as approved session")
	}
	source.version = 2
	r.Once(t.Context())
	got, err := os.ReadFile(file) // #nosec G304 -- this test reads only its own temporary renderer destination (CWE-22)
	defer secret.Wipe(got)
	if err != nil || !bytes.Equal(got, source.value) || leases.n != 0 {
		t.Fatal("exact initial session was not adopted")
	}
	if len(reports.verified) != 1 || reports.verified[0]["orders"] != 2 {
		t.Fatal("exact version was not reported after probe")
	}
	// A restart and missing file re-fetch the same publication, with no operator issue key.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	r, err = New(cfg, source, reports, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(leases)
	r.now = func() time.Time { return now }
	r.Once(t.Context())
	if leases.n != 0 {
		t.Fatal("bootstrap rewrite minted another session")
	}
	// Independent refresh must stop claiming the published V2 credential.
	reportCount := len(reports.verified)
	now = now.Add(11 * time.Minute)
	r.Once(t.Context())
	if leases.n != 1 || !leases.revoked["approved-L1"] {
		t.Fatal("verified replacement did not move into ordinary lease refresh")
	}
	for _, report := range reports.verified[reportCount:] {
		if report["orders"] != 0 {
			t.Fatal("L2 was falsely reported as exact published V2")
		}
	}
	reads := source.reads
	now = now.Add(11 * time.Minute)
	r.Once(t.Context())
	if leases.n != 2 || source.reads != reads {
		t.Fatal("refresh did not continue without reusing bootstrap")
	}
}

func TestReplacementPublicationBindingsA264(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	good := ReplacementPublication{ID: "11111111-1111-4111-8111-111111111111", State: "waiting_adoption", Action: "replace_key", Consumer: "orders", Provider: "sts", Role: "orders", LeaseID: "L1", NativeRoleID: "AROAEXACT", Version: 2, ExpectedVersion: 1, ExpiresAt: now.Add(15 * time.Minute)}
	cases := map[string]func(*ReplacementPublication){
		"consumer":        func(p *ReplacementPublication) { p.Consumer = "another" },
		"provider":        func(p *ReplacementPublication) { p.Provider = "another" },
		"role":            func(p *ReplacementPublication) { p.Role = "another" },
		"change":          func(p *ReplacementPublication) { p.ID = "another" },
		"action":          func(p *ReplacementPublication) { p.Action = "revoke_key" },
		"version":         func(p *ReplacementPublication) { p.Version = 3 },
		"native identity": func(p *ReplacementPublication) { p.NativeRoleID = "" },
		"expiry":          func(p *ReplacementPublication) { p.ExpiresAt = now },
		"pending":         func(p *ReplacementPublication) { p.State = "preparing_replacement" },
		"failed":          func(p *ReplacementPublication) { p.State = "failed" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := good
			mutate(&p)
			r := &Renderer{cfg: Config{Consumer: "orders"}, fetch: &replacementSource{publication: p}, now: func() time.Time { return now }}
			st := templateState{}
			err := r.prepareReplacement(t.Context(), Template{Replacement: &ReplacementBootstrap{ChangeID: good.ID, Provider: "sts", Role: "orders"}}, &st)
			if err == nil || len(st.Leases) > 0 {
				t.Fatal("unmatched publication admitted")
			}
		})
	}
}

func FuzzReplacementPublicationA264(f *testing.F) {
	f.Add([]byte(`{"id":"11111111-1111-4111-8111-111111111111","state":"waiting_adoption","intent":{"action":"replace_key","consumer":"orders","replacement_expected_version":1},"result":{"replacement_version":2,"replacement_expires_at":"2026-11-06T00:00:00Z"}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"result":{"replacement_version":"2"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		_, _ = decodeReplacementPublication(bytes.NewReader(raw))
	})
}
