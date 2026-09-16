// SPDX-License-Identifier: MPL-2.0

package sshtrust

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

type retryReloader struct {
	calls  []string
	failAt string
	cause  error
}

func (r *retryReloader) call(stage string) error {
	r.calls = append(r.calls, stage)
	if stage == r.failAt {
		return r.cause
	}
	return nil
}
func (r *retryReloader) Validate(context.Context) error    { return r.call("validate") }
func (r *retryReloader) Reload(context.Context) error      { return r.call("reload") }
func (r *retryReloader) HealthCheck(context.Context) error { return r.call("health-check") }

// The files can survive a killed agent while sshd still runs its old config.
// File presence must not stand in for validation, reload, and actual health.
func TestAddCATrustRetryVerifiesRunningDaemon(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failAt    string
		wantCalls []string
	}{
		{"success", "", []string{"validate", "reload", "health-check"}},
		{"validation refuses reload", "validate", []string{"validate"}},
		{"reload failure", "reload", []string{"validate", "reload"}},
		{"health failure", "health-check", []string{"validate", "reload", "health-check"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newMemFS()
			trust := "ssh-ed25519 AAAAexisting existing\n" + caLine + "\n"
			config := "Port 2222\nTrustedUserCAKeys " + trustPath + "\n"
			fs.files[trustPath] = []byte(trust)
			fs.files[cfgPath] = []byte(config)
			cause := errors.New("injected runtime verification failure")
			rl := &retryReloader{failAt: tc.failAt, cause: cause}
			rec := &auditsink.Recorder{}
			a := newApplier(t, fs, rl, rec)
			changed, err := a.AddCATrust(context.Background(), []byte(caLine))
			if changed {
				t.Error("retry rewrote existing trust")
			}
			if tc.failAt == "" && err != nil {
				t.Errorf("retry failed: %v", err)
			}
			if tc.failAt != "" && (!errors.Is(err, cause) || !strings.Contains(err.Error(), tc.failAt)) {
				t.Errorf("retry must surface the failed stage and cause: %v", err)
			}
			if !reflect.DeepEqual(rl.calls, tc.wantCalls) {
				t.Errorf("runtime calls = %v, want %v", rl.calls, tc.wantCalls)
			}
			if len(fs.writes) != 0 || string(fs.files[trustPath]) != trust || string(fs.files[cfgPath]) != config {
				t.Error("retry changed files or treated unverified on-disk bytes as a rollback backup")
			}
			for _, event := range []string{"ssh.trust.added", "ssh.trust.rolled_back", "ssh.trust.rollback_failed"} {
				if rec.Count(event) != 0 {
					t.Errorf("retry incorrectly emitted %s", event)
				}
			}
		})
	}
}

func TestAddCATrustRetryAfterCanceledContextDoesNotReload(t *testing.T) {
	fs := newMemFS()
	fs.files[trustPath] = []byte(caLine + "\n")
	fs.files[cfgPath] = []byte("TrustedUserCAKeys " + trustPath + "\n")
	rl := &retryReloader{}
	a := newApplier(t, fs, rl, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	changed, err := a.AddCATrust(ctx, []byte(caLine))
	if changed || !errors.Is(err, context.Canceled) || len(rl.calls) != 0 || len(fs.writes) != 0 {
		t.Fatalf("canceled retry: changed=%v err=%v calls=%v writes=%v", changed, err, rl.calls, fs.writes)
	}
}
