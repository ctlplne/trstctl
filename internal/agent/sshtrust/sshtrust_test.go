package sshtrust

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
)

type memFS struct{ files map[string][]byte }

func newMemFS() *memFS { return &memFS{files: map[string][]byte{}} }

func (m *memFS) ReadFile(p string) ([]byte, error) {
	b, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (m *memFS) WriteFileAtomic(p string, data []byte, _ os.FileMode) error {
	m.files[p] = append([]byte(nil), data...)
	return nil
}
func (m *memFS) Remove(p string) error { delete(m.files, p); return nil }
func (m *memFS) Exists(p string) bool  { _, ok := m.files[p]; return ok }

type fakeReloader struct {
	validateErr, reloadErr, healthErr error
	reloads                           int
}

func (r *fakeReloader) Validate(context.Context) error { return r.validateErr }
func (r *fakeReloader) Reload(context.Context) error   { r.reloads++; return r.reloadErr }
func (r *fakeReloader) HealthCheck(context.Context) error {
	return r.healthErr
}

const caLine = "ecdsa-sha2-nistp256 AAAAtestcakey ca@trustctl"
const trustPath = "/etc/ssh/trusted_user_ca_keys"
const cfgPath = "/etc/ssh/sshd_config"

func newApplier(t *testing.T, fs *memFS, rl Reloader, rec auditsink.Auditor) *Applier {
	t.Helper()
	a, err := New("t1", Config{
		FS: fs, Reloader: rl, SSHDConfigPath: cfgPath, TrustedUserCAKeysPath: trustPath,
		RequireConfirmationToRemoveTrust: true,
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
