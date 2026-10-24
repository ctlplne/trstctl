// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	sshprotocol "trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
)

type watchRoundTrip func(*http.Request) (*http.Response, error)

func (f watchRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type watchChecks struct {
	target  string
	reloads int
	health  int
}

func (w *watchChecks) ActiveKRLPath(context.Context, string) (string, error) { return w.target, nil }
func (w *watchChecks) ValidateKRL(_ context.Context, path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- test-only path under t.TempDir
	if err != nil {
		return err
	}
	_, err = sshkrl.Version(data)
	return err
}
func (w *watchChecks) ValidateSSHD(context.Context, string) error { return nil }
func (w *watchChecks) Reload(context.Context) error {
	w.reloads++
	return nil
}
func (w *watchChecks) Health(context.Context) error {
	w.health++
	return nil
}

func TestKRLWatchFetchBindsTenantAndSkipsUnchangedReload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "revoked_keys")
	old := sshprotocol.NewKRL().DistributeKRL(4)
	newList := sshprotocol.NewKRL()
	newList.RevokeSerial(101)
	next := newList.DistributeKRL(5)
	if err := os.WriteFile(target, old, 0o600); err != nil {
		t.Fatal(err)
	}
	checks := &watchChecks{target: target}
	client := &http.Client{Transport: watchRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://control.example/ssh/krl" || req.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("unexpected KRL request: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
			"Content-Type":        []string{"application/octet-stream"},
			"X-Trstctl-Tenant-Id": []string{"tenant-a"},
		}, Body: io.NopCloser(bytes.NewReader(next))}, nil
	})}
	o := sshKRLWatchOptions{URL: "https://control.example/ssh/krl", TenantID: "tenant-a", TargetPath: target,
		SSHDConfigPath: filepath.Join(dir, "sshd_config"), RollbackDir: filepath.Join(dir, "rollback")}
	for run := 0; run < 2; run++ {
		result, err := syncSSHKRLOnce(context.Background(), client, o, checks)
		if err != nil {
			t.Fatal(err)
		}
		if result.Changed != (run == 0) || result.Version != 5 {
			t.Fatalf("run %d: %+v", run, result)
		}
	}
	if checks.reloads != 1 || checks.health != 2 {
		t.Fatalf("unchanged poll restarted sshd: reloads=%d health=%d", checks.reloads, checks.health)
	}
	installed, err := os.ReadFile(target) // #nosec G304 -- test-only target under t.TempDir
	if err != nil || !bytes.Equal(installed, next) {
		t.Fatalf("installed KRL mismatch: %v", err)
	}
	if crypto.SHA256Hex(installed) != crypto.SHA256Hex(next) {
		t.Fatal("installed digest differs from response")
	}
}

func TestKRLWatchRefusesWrongTenantBeforeTouchingHost(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "revoked_keys")
	old := sshprotocol.NewKRL().DistributeKRL(4)
	if err := os.WriteFile(target, old, 0o600); err != nil {
		t.Fatal(err)
	}
	checks := &watchChecks{target: target}
	client := &http.Client{Transport: watchRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
			"Content-Type":        []string{"application/octet-stream"},
			"X-Trstctl-Tenant-Id": []string{"tenant-b"},
		}, Body: io.NopCloser(bytes.NewReader(sshprotocol.NewKRL().DistributeKRL(5)))}, nil
	})}
	o := sshKRLWatchOptions{URL: "https://control.example/ssh/krl", TenantID: "tenant-a", TargetPath: target,
		SSHDConfigPath: filepath.Join(dir, "sshd_config"), RollbackDir: filepath.Join(dir, "rollback")}
	if _, err := syncSSHKRLOnce(context.Background(), client, o, checks); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("cross-tenant KRL accepted: %v", err)
	}
	current, err := os.ReadFile(target) // #nosec G304 -- test-only target under t.TempDir
	if err != nil || !bytes.Equal(current, old) || checks.reloads != 0 {
		t.Fatalf("wrong tenant touched sshd: read=%v reloads=%d", err, checks.reloads)
	}
}

func TestKRLWatchRetainsLastGoodListOnBadResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		mediaType  string
		body       []byte
		bodyLength int64
	}{
		{name: "upstream unavailable", status: http.StatusServiceUnavailable, mediaType: "application/octet-stream"},
		{name: "login page", status: http.StatusOK, mediaType: "text/html", body: []byte("<html>login</html>")},
		{name: "truncated KRL", status: http.StatusOK, mediaType: "application/octet-stream", body: []byte("SSHKRL\n\x00")},
		{name: "oversized KRL", status: http.StatusOK, mediaType: "application/octet-stream", bodyLength: (128 << 20) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "revoked_keys")
			old := sshprotocol.NewKRL().DistributeKRL(4)
			if err := os.WriteFile(target, old, 0o600); err != nil {
				t.Fatal(err)
			}
			checks := &watchChecks{target: target}
			client := &http.Client{Transport: watchRoundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, ContentLength: tc.bodyLength, Header: http.Header{
					"Content-Type":        []string{tc.mediaType},
					"X-Trstctl-Tenant-Id": []string{"tenant-a"},
				}, Body: io.NopCloser(bytes.NewReader(tc.body))}, nil
			})}
			o := sshKRLWatchOptions{URL: "https://control.example/ssh/krl", TenantID: "tenant-a", TargetPath: target,
				SSHDConfigPath: filepath.Join(dir, "sshd_config"), RollbackDir: filepath.Join(dir, "rollback")}
			if _, err := syncSSHKRLOnce(context.Background(), client, o, checks); err == nil {
				t.Fatal("bad response changed host KRL")
			}
			current, err := os.ReadFile(target) // #nosec G304 -- test-only target under t.TempDir
			if err != nil || !bytes.Equal(current, old) || checks.reloads != 0 {
				t.Fatalf("bad response touched sshd: read=%v reloads=%d", err, checks.reloads)
			}
		})
	}
}

func TestKRLWatchRequiresHTTPSAndExplicitConfirmation(t *testing.T) {
	o := sshKRLWatchOptions{Enabled: true, URL: "http://control.example/ssh/krl", TenantID: "tenant-a", PollEvery: 15 * time.Second}
	if handled, err := runSSHKRLWatch(context.Background(), o, &watchChecks{}); !handled || err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("watch without confirmation: handled=%v err=%v", handled, err)
	}
	o.Confirm = true
	if handled, err := runSSHKRLWatch(context.Background(), o, &watchChecks{}); !handled || err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("watch with HTTP URL: handled=%v err=%v", handled, err)
	}
}

// A109: every watcher attempt leaves a receipt whose installed digest and
// version are read back from the RevokedKeys file, with how the attempt
// ended: installed, current, refused (and what the served list would drop),
// or a failed fetch that still reports what the host enforces.
func TestKRLWatchReceiptsReadBackWhatTheHostEnforces(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "revoked_keys")
	old := sshprotocol.NewKRL().DistributeKRL(4)
	if err := os.WriteFile(target, old, 0o600); err != nil {
		t.Fatal(err)
	}
	newer := sshprotocol.NewKRL()
	newer.RevokeSerial(101)
	newer.RevokeKeyID("pam:a")
	installedList := newer.DistributeKRL(5)
	dropping := sshprotocol.NewKRL()
	dropping.RevokeSerial(202)
	droppingList := dropping.DistributeKRL(6)

	var serve []byte
	fail := false
	client := &http.Client{Transport: watchRoundTrip(func(*http.Request) (*http.Response, error) {
		if fail {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
			"Content-Type":        []string{"application/octet-stream"},
			"X-Trstctl-Tenant-Id": []string{"tenant-a"},
		}, Body: io.NopCloser(bytes.NewReader(serve))}, nil
	})}
	receipts := &sshKRLReceipts{}
	o := sshKRLWatchOptions{URL: "https://control.example/ssh/krl", TenantID: "tenant-a", TargetPath: target,
		SSHDConfigPath: filepath.Join(dir, "sshd_config"), RollbackDir: filepath.Join(dir, "rollback"), Receipts: receipts,
		PollEvery: 30 * time.Second}
	checks := &watchChecks{target: target}
	clock := time.Unix(1_800_000_000, 0)
	attempt := func() *sshkrlreceipt.Receipt {
		t.Helper()
		clock = clock.Add(time.Minute)
		_, receipt, _ := attemptSSHKRL(context.Background(), client, o, checks, func() time.Time { return clock })
		receipts.record(receipt)
		latest := receipts.Latest()
		if latest == nil {
			t.Fatal("attempt left no receipt")
		}
		if err := (sshkrlreceipt.Statement{TenantID: "tenant-a", AgentCommonName: "edge-1", Receipt: *latest, IssuedAtUnix: clock.Unix()}).Validate(); err != nil {
			t.Fatalf("receipt %+v does not validate: %v", latest, err)
		}
		return latest
	}

	serve = installedList
	if r := attempt(); r.Outcome != sshkrlreceipt.OutcomeInstalled || r.InstalledSHA256 != crypto.SHA256Hex(installedList) || r.InstalledVersion != 5 || r.InstalledAtUnix != clock.Unix() {
		t.Fatalf("install receipt = %+v", r)
	}
	installedAt := clock.Unix()
	if r := attempt(); r.Outcome != sshkrlreceipt.OutcomeCurrent || r.InstalledAtUnix != installedAt {
		t.Fatalf("unchanged receipt = %+v", r)
	}
	serve = droppingList
	if r := attempt(); r.Outcome != sshkrlreceipt.OutcomeRefusedDropsRevocations || r.DroppedSerials != 1 || r.DroppedKeyIDs != 1 ||
		r.InstalledSHA256 != crypto.SHA256Hex(installedList) || r.FetchedSHA256 != crypto.SHA256Hex(droppingList) || r.FetchedVersion != 6 {
		t.Fatalf("refusal receipt = %+v", r)
	}
	serve = old
	if r := attempt(); r.Outcome != sshkrlreceipt.OutcomeRefusedNotNewer || r.FetchedVersion != 4 {
		t.Fatalf("older list receipt = %+v", r)
	}
	fail = true
	if r := attempt(); r.Outcome != sshkrlreceipt.OutcomeFetchFailed || r.InstalledSHA256 != crypto.SHA256Hex(installedList) || r.FetchedSHA256 != "" {
		t.Fatalf("fetch failure receipt = %+v", r)
	}
	// The newest receipt canonicalizes for signing onto the heartbeat.
	report, err := transport.SignedSSHKRLReceipt(recordingSigner{}, "tenant-a", "edge-1", *receipts.Latest(), clock.Unix())
	if err != nil || !bytes.HasPrefix(report.Signature, []byte("trstctl-agent-ssh-krl-receipt/v1\n")) {
		t.Fatalf("sign receipt: %+v %v", report, err)
	}
}

// recordingSigner returns the statement it was asked to sign.
type recordingSigner struct{}

func (recordingSigner) SignStatement(statement []byte) ([]byte, error) { return statement, nil }
