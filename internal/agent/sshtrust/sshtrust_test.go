// SPDX-License-Identifier: MPL-2.0

package sshtrust

import (
	"context"
	"errors"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

type memFS struct {
	files         map[string][]byte
	writes        map[string]int
	writeErr      map[string]error
	writeErrAfter map[string]int
	removeErr     map[string]error
	readErr       map[string]error
}

func newMemFS() *memFS {
	return &memFS{
		files:         map[string][]byte{},
		writes:        map[string]int{},
		writeErr:      map[string]error{},
		writeErrAfter: map[string]int{},
		removeErr:     map[string]error{},
		readErr:       map[string]error{},
	}
}

func (m *memFS) ReadFile(p string) ([]byte, error) {
	if err, ok := m.readErr[p]; ok {
		return nil, err
	}
	b, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (m *memFS) WriteFileAtomic(p string, data []byte, _ os.FileMode) error {
	m.writes[p]++
	if err, ok := m.writeErr[p]; ok && m.writes[p] > m.writeErrAfter[p] {
		return err
	}
	m.files[p] = append([]byte(nil), data...)
	return nil
}
func (m *memFS) Remove(p string) error {
	if err, ok := m.removeErr[p]; ok {
		return err
	}
	delete(m.files, p)
	return nil
}
func (m *memFS) Exists(p string) bool { _, ok := m.files[p]; return ok }
func (m *memFS) Glob(pattern string) ([]string, error) {
	var matches []string
	for p := range m.files {
		ok, err := path.Match(pattern, strings.ReplaceAll(p, `\`, `/`))
		if err != nil {
			return nil, err
		}
		if ok {
			matches = append(matches, p)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func (m *memFS) failWritesAfter(path string, successfulWrites int, err error) {
	m.writeErr[path] = err
	m.writeErrAfter[path] = successfulWrites
}

func (m *memFS) failRemove(path string, err error) {
	m.removeErr[path] = err
}

// failRead makes a file that EXISTS unreadable — permission denied, an I/O
// error, a race with another writer. Distinct from absence, which is what the
// applier used to conflate it with.
func (m *memFS) failRead(path string, err error) {
	m.readErr[path] = err
}

type fakeReloader struct {
	validateErr, reloadErr, healthErr error
	reloads                           int
	reloadErrOnCall                   int
}

func (r *fakeReloader) Validate(context.Context) error { return r.validateErr }
func (r *fakeReloader) Reload(context.Context) error {
	r.reloads++
	if r.reloadErr != nil && (r.reloadErrOnCall == 0 || r.reloads == r.reloadErrOnCall) {
		return r.reloadErr
	}
	return nil
}
func (r *fakeReloader) HealthCheck(context.Context) error {
	return r.healthErr
}

const caLine = "ecdsa-sha2-nistp256 AAAAtestcakey ca@trstctl"
const trustPath = "/etc/ssh/trusted_user_ca_keys"
const cfgPath = "/etc/ssh/sshd_config"

func newApplier(t *testing.T, fs *memFS, rl Reloader, rec auditsink.Auditor) *Applier {
	t.Helper()
	// Deliberately do NOT set AllowUnconfirmedRemoval: the safe default (zero value
	// false) must require confirmation to remove trust (SIGNER-007).
	a, err := New("t1", Config{
		FS: fs, Reloader: rl, SSHDConfigPath: cfgPath, TrustedUserCAKeysPath: trustPath,
	}, rec)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAddCATrustHappyPath(t *testing.T) {
	fs := newMemFS()
	rl := &fakeReloader{}
	rec := &auditsink.Recorder{}
	a := newApplier(t, fs, rl, rec)
	changed, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err != nil || !changed {
		t.Fatalf("AddCATrust: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Error("CA line not written to trust file")
	}
	if !strings.Contains(string(fs.files[cfgPath]), "TrustedUserCAKeys "+trustPath) {
		t.Error("sshd_config does not reference the trust file")
	}
	if rl.reloads != 1 {
		t.Errorf("reloads = %d, want 1", rl.reloads)
	}
	if rec.Count("ssh.trust.added") != 1 {
		t.Error("trust change not audited")
	}
}

func TestAddCATrustIdempotent(t *testing.T) {
	fs := newMemFS()
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	changed, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("second AddCATrust reported a change (not idempotent)")
	}
	if strings.Count(string(fs.files[trustPath]), caLine) != 1 {
		t.Error("CA line duplicated")
	}
}

func TestAddCATrustIsAdditive(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte("ssh-ed25519 AAAAexisting other-ca@corp\n")
	fs.files[cfgPath] = []byte("Port 2222\nPermitRootLogin no\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	trust := string(fs.files[trustPath])
	if !strings.Contains(trust, "other-ca@corp") || !strings.Contains(trust, caLine) {
		t.Errorf("trust file not additive: %q", trust)
	}
	cfg := string(fs.files[cfgPath])
	if !strings.Contains(cfg, "Port 2222") || !strings.Contains(cfg, "PermitRootLogin no") {
		t.Errorf("existing sshd_config directives lost: %q", cfg)
	}
}

func TestAddCATrustIgnoresCommentedSSHDDirective(t *testing.T) {
	fs := newMemFS()
	fs.files[cfgPath] = []byte("# TrustedUserCAKeys " + trustPath + "\nPort 22\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	cfg := string(fs.files[cfgPath])
	if got := activeTrustedKeysDirectives(cfg, cfgPath, trustPath); got != 1 {
		t.Fatalf("active TrustedUserCAKeys directives = %d, want one appended directive; cfg=%q", got, cfg)
	}
	if !strings.Contains(cfg, "# TrustedUserCAKeys "+trustPath) {
		t.Fatalf("commented operator config was not preserved: %q", cfg)
	}
}

func TestAddCATrustRepairsConfigWhenCAAlreadyPresentButDirectiveCommented(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte(caLine + "\n")
	fs.files[cfgPath] = []byte("# TrustedUserCAKeys " + trustPath + "\nPort 22\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	changed, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("AddCATrust reported idempotent no-op while sshd_config only had a commented directive")
	}
	cfg := string(fs.files[cfgPath])
	if got := activeTrustedKeysDirectives(cfg, cfgPath, trustPath); got != 1 {
		t.Fatalf("active TrustedUserCAKeys directives = %d, want one repaired directive; cfg=%q", got, cfg)
	}
	if strings.Count(string(fs.files[trustPath]), caLine) != 1 {
		t.Fatalf("repair duplicated CA line in trust file: %q", fs.files[trustPath])
	}
}

func TestAddCATrustDoesNotDuplicateActiveSSHDDirective(t *testing.T) {
	fs := newMemFS()
	fs.files[cfgPath] = []byte("TrustedUserCAKeys    \"" + trustPath + "\" # managed by operator\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	cfg := string(fs.files[cfgPath])
	if got := activeTrustedKeysDirectives(cfg, cfgPath, trustPath); got != 1 {
		t.Fatalf("active TrustedUserCAKeys directives = %d, want no duplicate; cfg=%q", got, cfg)
	}
}

func TestAddCATrustHonorsIncludedSSHDDirective(t *testing.T) {
	fs := newMemFS()
	includePath := "/etc/ssh/sshd_config.d/10-trust.conf"
	fs.files[cfgPath] = []byte("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
	fs.files[includePath] = []byte("TrustedUserCAKeys " + trustPath + "\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	cfg := string(fs.files[cfgPath])
	if got := activeTrustedKeysDirectives(cfg, cfgPath, trustPath); got != 0 {
		t.Fatalf("main sshd_config gained a duplicate directive despite active include, got %d; cfg=%q", got, cfg)
	}
	if !strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Fatal("CA was not added to the configured trust file")
	}
}

func TestAddCATrustIgnoresCommentedIncludedSSHDDirective(t *testing.T) {
	fs := newMemFS()
	includePath := "/etc/ssh/sshd_config.d/10-trust.conf"
	fs.files[cfgPath] = []byte("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
	fs.files[includePath] = []byte("# TrustedUserCAKeys " + trustPath + "\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err != nil {
		t.Fatal(err)
	}
	cfg := string(fs.files[cfgPath])
	if got := activeTrustedKeysDirectives(cfg, cfgPath, trustPath); got != 1 {
		t.Fatalf("commented included directive suppressed active append, got %d; cfg=%q", got, cfg)
	}
}

func TestAddCATrustRollsBackOnValidateFailure(t *testing.T) {
	fs := newMemFS()
	origTrust := "ssh-ed25519 AAAAexisting other-ca\n"
	origCfg := "Port 22\n"
	fs.files[trustPath] = []byte(origTrust)
	fs.files[cfgPath] = []byte(origCfg)
	rl := &fakeReloader{validateErr: errors.New("bad config")}
	rec := &auditsink.Recorder{}
	a := newApplier(t, fs, rl, rec)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err == nil {
		t.Fatal("expected an error when validation fails")
	}
	if string(fs.files[trustPath]) != origTrust || string(fs.files[cfgPath]) != origCfg {
		t.Error("files were not restored to last-known-good after validate failure")
	}
	if rec.Count("ssh.trust.rolled_back") != 1 {
		t.Error("rollback not audited")
	}
}

func TestAddCATrustRollsBackOnHealthFailure(t *testing.T) {
	fs := newMemFS()
	origTrust := "existing\n"
	fs.files[trustPath] = []byte(origTrust)
	fs.files[cfgPath] = []byte("Port 22\n")
	rl := &fakeReloader{healthErr: errors.New("sshd not accepting connections")}
	a := newApplier(t, fs, rl, nil)
	if _, err := a.AddCATrust(context.Background(), []byte(caLine)); err == nil {
		t.Fatal("expected an error when the post-reload health check fails")
	}
	if string(fs.files[trustPath]) != origTrust {
		t.Errorf("trust file not rolled back: %q", fs.files[trustPath])
	}
	// rollback reloads the restored config (initial reload + rollback reload).
	if rl.reloads < 2 {
		t.Errorf("expected a rollback reload, reloads=%d", rl.reloads)
	}
}

func TestAddCATrustSurfacesRollbackWriteFailure(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte("existing\n")
	fs.files[cfgPath] = []byte("Port 22\n")
	fs.failWritesAfter(trustPath, 1, errors.New("restore trust denied"))
	rl := &fakeReloader{validateErr: errors.New("bad config")}
	rec := &auditsink.Recorder{}
	a := newApplier(t, fs, rl, rec)

	_, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err == nil {
		t.Fatal("expected validate failure plus rollback write failure")
	}
	for _, want := range []string{"rollback failed", "bad config", "restore trust denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if rec.Count("ssh.trust.rollback_failed") != 1 {
		t.Fatal("failed rollback was not audited")
	}
	if rec.Count("ssh.trust.rolled_back") != 0 {
		t.Fatal("failed rollback must not be audited as successful")
	}
}

func TestAddCATrustSurfacesRollbackRemoveFailure(t *testing.T) {
	fs := newMemFS()
	fs.files[cfgPath] = []byte("Port 22\n")
	fs.failRemove(trustPath, errors.New("remove denied"))
	rl := &fakeReloader{validateErr: errors.New("bad config")}
	rec := &auditsink.Recorder{}
	a := newApplier(t, fs, rl, rec)

	_, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err == nil {
		t.Fatal("expected validate failure plus rollback remove failure")
	}
	for _, want := range []string{"rollback failed", "bad config", "remove denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if rec.Count("ssh.trust.rollback_failed") != 1 {
		t.Fatal("failed rollback was not audited")
	}
	if rec.Count("ssh.trust.rolled_back") != 0 {
		t.Fatal("failed rollback must not be audited as successful")
	}
}

func TestAddCATrustSurfacesRollbackReloadFailure(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte("existing\n")
	fs.files[cfgPath] = []byte("Port 22\n")
	rl := &fakeReloader{
		healthErr:       errors.New("sshd unhealthy"),
		reloadErr:       errors.New("reload refused"),
		reloadErrOnCall: 2,
	}
	rec := &auditsink.Recorder{}
	a := newApplier(t, fs, rl, rec)

	_, err := a.AddCATrust(context.Background(), []byte(caLine))
	if err == nil {
		t.Fatal("expected health failure plus rollback reload failure")
	}
	for _, want := range []string{"rollback failed", "sshd unhealthy", "reload refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if rec.Count("ssh.trust.rollback_failed") != 1 {
		t.Fatal("failed rollback was not audited")
	}
	if rec.Count("ssh.trust.rolled_back") != 0 {
		t.Fatal("failed rollback must not be audited as successful")
	}
}

func TestRemoveTrustRequiresConfirmation(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte(caLine + "\n")
	fs.files[cfgPath] = []byte("Port 22\n")
	a := newApplier(t, fs, &fakeReloader{}, nil)
	if err := a.RemoveCATrust(context.Background(), []byte(caLine), false); err == nil {
		t.Error("removed trust without confirmation")
	}
	if !strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Error("trust line removed despite missing confirmation")
	}
	if err := a.RemoveCATrust(context.Background(), []byte(caLine), true); err != nil {
		t.Fatalf("confirmed removal failed: %v", err)
	}
	if strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Error("trust line not removed after confirmation")
	}
}

// TestZeroValueConfigRequiresConfirmation is the SIGNER-007 acceptance: a
// default-constructed Config (no AllowUnconfirmedRemoval) must reject an
// unconfirmed removal. This pins the safe default — the pre-fix code gated on
// RequireConfirmationToRemoveTrust whose zero value (false) let an unconfirmed
// removal through, contradicting the project's trust-removal rule.
func TestZeroValueConfigRequiresConfirmation(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte(caLine + "\n")
	fs.files[cfgPath] = []byte("Port 22\n")
	// A zero-value Config except for the required wiring; AllowUnconfirmedRemoval is
	// its zero value (false).
	a, err := New("t1", Config{
		FS: fs, Reloader: &fakeReloader{}, SSHDConfigPath: cfgPath, TrustedUserCAKeysPath: trustPath,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveCATrust(context.Background(), []byte(caLine), false); err == nil {
		t.Fatal("zero-value Config removed trust without confirmation (SIGNER-007 regression)")
	}
	if !strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Error("trust line removed despite the safe default requiring confirmation")
	}
}

// TestAllowUnconfirmedRemovalOptOut confirms the explicit opt-out still works: a
// Config that deliberately sets AllowUnconfirmedRemoval=true may remove without
// confirm, for automated teardowns that supply confirmation out of band.
func TestAllowUnconfirmedRemovalOptOut(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte(caLine + "\n")
	fs.files[cfgPath] = []byte("Port 22\n")
	a, err := New("t1", Config{
		FS: fs, Reloader: &fakeReloader{}, SSHDConfigPath: cfgPath, TrustedUserCAKeysPath: trustPath,
		AllowUnconfirmedRemoval: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveCATrust(context.Background(), []byte(caLine), false); err != nil {
		t.Fatalf("opt-out removal failed: %v", err)
	}
	if strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Error("trust line not removed under the explicit opt-out")
	}
}

func activeTrustedKeysDirectives(content, configPath, trustedKeysPath string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		fields := sshdConfigFields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "TrustedUserCAKeys") && sameSSHDPath(configPath, fields[1], trustedKeysPath) {
			count++
		}
	}
	return count
}
