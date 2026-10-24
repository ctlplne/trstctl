// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

// hostKRLChecks stands in for one relying host's sshd: the KRL is checked by
// stock ssh-keygen where it is installed, so the served artifact must be a
// list OpenSSH reads.
type hostKRLChecks struct{ target string }

func (c hostKRLChecks) ActiveKRLPath(context.Context, string) (string, error) { return c.target, nil }
func (c hostKRLChecks) ValidateKRL(ctx context.Context, path string) error {
	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		if out, err := exec.CommandContext(ctx, keygen, "-Q", "-l", "-f", path).CombinedOutput(); err != nil { // #nosec G204 -- fixed ssh-keygen argv over a test-owned temp path
			return errors.New(string(out))
		}
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned KRL path under t.TempDir
	if err != nil {
		return err
	}
	_, err = sshkrl.ParseRevocations(data)
	return err
}
func (hostKRLChecks) ValidateSSHD(context.Context, string) error { return nil }
func (hostKRLChecks) Reload(context.Context) error               { return nil }
func (hostKRLChecks) Health(context.Context) error               { return nil }

// relyingHost is a host whose RevokedKeys file holds installed.
func relyingHost(t *testing.T, installed []byte) sshkrl.Config {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "revoked_keys")
	if err := os.WriteFile(target, installed, 0o600); err != nil { // #nosec G703 -- target is a fixed name under t.TempDir, not request-derived
		t.Fatal(err)
	}
	return sshkrl.Config{TargetPath: target, SSHDConfigPath: filepath.Join(dir, "sshd_config"),
		RollbackDir: filepath.Join(dir, "rollbacks"), Checks: hostKRLChecks{target: target}, SkipReloadOnUnchanged: true}
}

func servedKRL(t *testing.T, h *servedHarness) []byte {
	t.Helper()
	resp, err := h.ts.Client().Get(h.ts.URL + "/ssh/krl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ssh/krl = %d %s", resp.StatusCode, data)
	}
	return data
}

func adoptKRL(t *testing.T, h *servedHarness, token, key string, krl []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/ssh/krl/adoptions", bytes.NewReader(krl))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Idempotency-Key", key)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

type krlAdoptionResult struct {
	Parts          int  `json:"parts"`
	AlreadyCarried bool `json:"already_carried"`
	Carried        struct {
		SerialRanges     int `json:"serial_ranges"`
		KeyIDs           int `json:"key_ids"`
		BroadenedToAnyCA int `json:"broadened_to_any_ca"`
	} `json:"carried"`
	PredecessorVersion uint64 `json:"predecessor_version"`
	KRL                struct {
		KRLVersion   uint64 `json:"krl_version"`
		RevokedCount int    `json:"revoked_count"`
	} `json:"krl"`
}

// A110: a host moves from its predecessor control plane's KRL lineage to a
// replacement's only after the replacement carries every predecessor
// revocation and has moved its version past the predecessor's. Before the
// adoption the host keeps its list; after it the host takes the new list, a
// stock ssh-keygen reads it, and a cold replay of the log serves it unchanged.
func TestServedSSHKRLAdoptionCarriesAPredecessorLineage(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	token := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read")

	// The predecessor control plane's list as a host installed it: its own
	// count (40), two adjacent serials, and a PAM key ID.
	old := sshca.NewKRL()
	old.RevokeSerial(1001)
	old.RevokeSerial(1002)
	old.RevokeKeyID("pam:predecessor")
	predecessor := old.DistributeKRL(40)
	host := relyingHost(t, predecessor)

	// This control plane has its own revocation and its own, lower, count.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", token, "a110-own", map[string]any{"serial": 7}); status != http.StatusOK {
		t.Fatalf("revoke = %d %s", status, body)
	}
	if _, err := sshkrl.Apply(t.Context(), host, servedKRL(t, h), crypto.SHA256Hex(servedKRL(t, h))); !errors.Is(err, sshkrl.ErrNotNewer) {
		t.Fatalf("host took the replacement list before adoption: %v", err)
	}

	status, body := adoptKRL(t, h, token, "a110-adopt-1", predecessor)
	var adopted krlAdoptionResult
	if status != http.StatusOK || json.Unmarshal(body, &adopted) != nil || adopted.Parts != 1 || adopted.AlreadyCarried ||
		adopted.Carried.SerialRanges != 1 || adopted.Carried.KeyIDs != 1 || adopted.PredecessorVersion != 40 || adopted.KRL.KRLVersion <= 40 {
		t.Fatalf("adopt = %d %s", status, body)
	}
	if status, replay := adoptKRL(t, h, token, "a110-adopt-1", predecessor); status != http.StatusOK || !bytes.Equal(replay, body) {
		t.Fatalf("idempotent replay = %d %s", status, replay)
	}
	status, body = adoptKRL(t, h, token, "a110-adopt-again", predecessor)
	var again krlAdoptionResult
	if status != http.StatusOK || json.Unmarshal(body, &again) != nil || !again.AlreadyCarried || again.Parts != 0 || again.KRL.KRLVersion != adopted.KRL.KRLVersion {
		t.Fatalf("adopting a carried list again = %d %s", status, body)
	}

	served := servedKRL(t, h)
	result, err := sshkrl.Apply(t.Context(), host, served, crypto.SHA256Hex(served))
	if err != nil || !result.Changed || result.PreviousVersion != 40 || result.Version != adopted.KRL.KRLVersion {
		t.Fatalf("host refused the adopted list: %+v %v", result, err)
	}
	installed, err := sshkrl.ParseRevocations(served)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{predecessor, sshca.NewKRL().DistributeKRL(0)} {
		have, err := sshkrl.ParseRevocations(want)
		if err != nil {
			t.Fatal(err)
		}
		if drop := installed.Dropped(have); !drop.Empty() {
			t.Fatalf("the served list drops predecessor revocations: %+v", drop)
		}
	}
	own := sshca.NewKRL()
	own.RevokeSerial(7)
	if have, _ := sshkrl.ParseRevocations(own.DistributeKRL(1)); !func() bool { d := installed.Dropped(have); return d.Empty() }() {
		t.Fatal("the served list lost this control plane's own revocation")
	}

	// An operator's own CA-scoped list (written by stock ssh-keygen) is carried
	// for any CA, so a host holding it also takes the served list.
	scoped, err := os.ReadFile(filepath.Join("..", "agent", "sshkrl", "testdata", "ssh-keygen-ca-scoped.krl"))
	if err != nil {
		t.Fatal(err)
	}
	status, body = adoptKRL(t, h, token, "a110-adopt-scoped", scoped)
	var broadened krlAdoptionResult
	if status != http.StatusOK || json.Unmarshal(body, &broadened) != nil || broadened.Carried.BroadenedToAnyCA != 3 || broadened.Parts != 1 {
		t.Fatalf("adopt CA-scoped list = %d %s", status, body)
	}
	served = servedKRL(t, h)
	if _, err := sshkrl.Apply(t.Context(), relyingHost(t, scoped), served, crypto.SHA256Hex(served)); err != nil {
		t.Fatalf("host holding the operator list refused the served list: %v", err)
	}

	// A cold replay of the log serves the same list.
	restored, err := newSSHProtocol(h.srv.protocols.ssh.ca, h.tenant, h.srv.protocols.ssh.guard, h.srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.restoreRevocations(context.Background(), h.log); err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	if !bytes.Equal(restored.KRLBytes(), served) {
		t.Fatal("cold replay served a different KRL")
	}

	// Refusals record nothing.
	versionBefore := restored.KRLVersion()
	for name, krl := range map[string][]byte{
		"not a KRL":     []byte("revoked serials: 1, 2, 3"),
		"key not a key": badKeyKRL(),
	} {
		if status, body := adoptKRL(t, h, token, "a110-refuse-"+name, krl); status != http.StatusUnprocessableEntity {
			t.Fatalf("%s: adopt = %d %s", name, status, body)
		}
	}
	if status, body := adoptKRL(t, h, token, "a110-empty", nil); status != http.StatusBadRequest {
		t.Fatalf("empty body: adopt = %d %s", status, body)
	}
	if v := h.srv.protocols.ssh.KRLVersion(); v != versionBefore {
		t.Fatalf("a refused adoption moved the KRL version %d -> %d", versionBefore, v)
	}
}

// badKeyKRL is a list that revokes an "explicit key" which is not an SSH key.
func badKeyKRL() []byte {
	k := sshca.NewKRL()
	k.RevokeKey([]byte("not a public key"))
	return k.DistributeKRL(2)
}
