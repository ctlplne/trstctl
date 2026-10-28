// SPDX-License-Identifier: BUSL-1.1

package sshtrust

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const observedCA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt fleet-public-fixture"

type cancelHealthReloader struct {
	cancel              context.CancelFunc
	reloads, health     int
	cleanupCanceled     bool
	rollbackHealthFails bool
}

func (r *cancelHealthReloader) Validate(ctx context.Context) error { return ctx.Err() }
func (r *cancelHealthReloader) Reload(ctx context.Context) error {
	r.reloads++
	if ctx.Err() != nil {
		r.cleanupCanceled = true
	}
	return ctx.Err()
}
func (r *cancelHealthReloader) HealthCheck(ctx context.Context) error {
	r.health++
	if r.health == 1 {
		r.cancel()
		return errors.New("health attempt canceled")
	}
	if r.rollbackHealthFails {
		return errors.New("restored daemon still unhealthy")
	}
	return ctx.Err()
}

func TestObservedSSHTrustReadsBackFilesAndRetriesRuntimeChecks(t *testing.T) {
	fs := newMemFS()
	fs.files[cfgPath] = []byte("Port 22\n")
	r := &fakeReloader{}
	a := newApplier(t, fs, r, nil)
	first, err := a.AddCATrustObserved(context.Background(), []byte(observedCA))
	if err != nil || !first.Changed || !first.CAReadBack || !first.EffectiveConfigReadBack || !first.Validated || !first.Reloaded || !first.Healthy || first.Phase != "complete" || first.Rollback != "not_needed" || first.TrustFileSHA256 == "" || first.ConfigFileSHA256 == "" {
		t.Fatalf("missing applied effect: %+v %v", first, err)
	}
	before := r.reloads
	second, err := a.AddCATrustObserved(context.Background(), []byte(observedCA))
	if err != nil || second.Changed || !second.CAReadBack || !second.Healthy || r.reloads != before+1 {
		t.Fatalf("retry did not check runtime: %+v %v", second, err)
	}
	if strings.Count(string(fs.files[trustPath]), observedCA) != 1 {
		t.Fatal("retry duplicated public trust")
	}
}

func TestObservedSSHTrustCancellationGetsBoundedVerifiedRollback(t *testing.T) {
	for _, healthFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "failed"}[healthFails], func(t *testing.T) {
			fs := newMemFS()
			fs.files[cfgPath] = []byte("Port 22\n")
			fs.files[trustPath] = []byte("prior-public-trust\n")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &cancelHealthReloader{cancel: cancel, rollbackHealthFails: healthFails}
			result, err := newApplier(t, fs, r, nil).AddCATrustObserved(ctx, []byte(observedCA))
			want := "verified"
			if healthFails {
				want = "failed"
			}
			if err == nil || result.Phase != "health" || result.Rollback != want || r.cleanupCanceled || r.reloads < 2 {
				t.Fatalf("false rollback: %+v err=%v reloads=%d canceled=%v", result, err, r.reloads, r.cleanupCanceled)
			}
			if string(fs.files[cfgPath]) != "Port 22\n" || string(fs.files[trustPath]) != "prior-public-trust\n" {
				t.Fatal("did not restore exact prior bytes")
			}
		})
	}
}

type observedReadbackFaultFS struct {
	*memFS
	mode  string
	armed bool
}

func (f *observedReadbackFaultFS) ReadFile(path string) ([]byte, error) {
	if path == trustPath && f.armed {
		f.armed = false
		if f.mode == "io" {
			return nil, errors.New("injected post-health readback I/O failure")
		}
		return []byte("# requested CA not observed\n"), nil
	}
	return f.memFS.ReadFile(path)
}

type observedReadbackFaultReloader struct {
	fs              *observedReadbackFaultFS
	health, reloads int
}

func (r *observedReadbackFaultReloader) Validate(ctx context.Context) error { return ctx.Err() }
func (r *observedReadbackFaultReloader) Reload(ctx context.Context) error {
	r.reloads++
	return ctx.Err()
}
func (r *observedReadbackFaultReloader) HealthCheck(ctx context.Context) error {
	r.health++
	if r.health == 1 {
		r.fs.armed = true
	}
	return ctx.Err()
}
func TestObservedSSHTrustReadbackFailureRestoresExactPriorTrust(t *testing.T) {
	for _, mode := range []string{"io", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			fs := &observedReadbackFaultFS{memFS: newMemFS(), mode: mode}
			fs.files[cfgPath] = []byte("Port 22\n")
			fs.files[trustPath] = []byte("# prior empty public trust list\n")
			checks := &observedReadbackFaultReloader{fs: fs}
			a, err := New("observed-readback", Config{FS: fs, Reloader: checks, SSHDConfigPath: cfgPath, TrustedUserCAKeysPath: trustPath}, nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := a.AddCATrustObserved(t.Context(), []byte(observedCA))
			if err == nil || result.Phase != "readback" || result.Rollback != "verified" || checks.health < 2 || checks.reloads < 2 {
				t.Fatalf("post-health readback failure left changed SSH trust without checked recovery: %+v err=%v checks=%+v", result, err, checks)
			}
			if string(fs.files[cfgPath]) != "Port 22\n" || string(fs.files[trustPath]) != "# prior empty public trust list\n" {
				t.Fatal("readback failure did not restore exact prior file bytes")
			}
		})
	}
}
