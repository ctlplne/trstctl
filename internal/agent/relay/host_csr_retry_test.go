// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type pendingCSRChannel struct {
	renewChannel
	extensions int
}

type controlledRenewalChannel struct {
	renewChannel
	extend func(context.Context, int64, int) (time.Time, error)
	sign   func(context.Context, []byte, int) ([]byte, []byte, string, error)
}

func (c *controlledRenewalChannel) ExtendJobClaim(ctx context.Context, job int64, attempt int) (time.Time, error) {
	return c.extend(ctx, job, attempt)
}

func (c *controlledRenewalChannel) SignJobCSR(ctx context.Context, job int64, attempt int, csr []byte) ([]byte, []byte, string, error) {
	if job != 77 || attempt != 1 {
		return nil, nil, "", errors.New("changed job or attempt")
	}
	c.signCalls++
	c.signed = append(c.signed, bytes.Clone(csr))
	return c.sign(ctx, csr, c.signCalls)
}

// Exercise the real locked subject key and file connector. The allowlisted
// subprocess is the test binary, not a Caddy service qualification.
func TestHostRenewalPendingRecoveryAndAuthorityBoundaries(t *testing.T) {
	for _, mode := range []string{"late-success", "transport-recovery", "claim-lost-during-signing", "claim-lost-before-install", "cancelled", "permanent-refusal"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			defer caKey.Destroy()
			caDER, err := crypto.SelfSignedCACert(caKey, "pending-renewal-fixture", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			var extensions atomic.Int64
			c := &controlledRenewalChannel{}
			c.extend = func(ctx context.Context, job int64, attempt int) (time.Time, error) {
				if job != 77 || attempt != 1 {
					return time.Time{}, relay.ErrJobClaimLost
				}
				n := extensions.Add(1)
				if n > 1 && (mode == "claim-lost-during-signing" || mode == "claim-lost-before-install") {
					return time.Time{}, relay.ErrJobClaimLost
				}
				return time.Now().Add(300 * time.Millisecond), ctx.Err()
			}
			c.sign = func(ctx context.Context, csr []byte, call int) ([]byte, []byte, string, error) {
				if mode == "permanent-refusal" {
					return nil, nil, "", status.Error(codes.PermissionDenied, "refused")
				}
				if mode == "cancelled" || mode == "claim-lost-during-signing" {
					<-ctx.Done()
					return nil, nil, "", ctx.Err()
				}
				if call == 1 && mode != "claim-lost-before-install" {
					if mode == "transport-recovery" {
						return nil, nil, "", status.Error(codes.Unavailable, "lost reply")
					}
					return nil, nil, "", transport.CSRPendingError()
				}
				// A reply outlives the original short claim, requiring periodic
				// extension while the same key remains locked on this host.
				if mode != "claim-lost-before-install" {
					select {
					case <-ctx.Done():
						return nil, nil, "", ctx.Err()
					case <-time.After(350 * time.Millisecond):
					}
				}
				der, err := crypto.SignLeafFromCSR(caDER, caKey, csr, 30*time.Minute)
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), crypto.SHA256Hex(der), err
			}
			c.jobs = []relay.Job{renewJob(t, relay.DeployIntent{Connector: "caddy", Target: "pending-host", SubjectCommonName: "pending.example.test", TargetConfig: renewTargetConfig(t, certPath, keyPath)})}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			profile := connector.LocalOpsConfig{AllowedRoots: []string{dir}, Actions: []connector.LocalAction{
				{LogicalName: "caddy", LogicalArgs: []string{"reload"}, Command: exe, Args: []string{"-test.run=^$"}},
			}}
			limit := 5 * time.Second
			if mode == "cancelled" {
				limit = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), limit)
			defer cancel()
			executed, err := relay.RunOnceWithHost(ctx, c, http.DefaultClient, profile, 1, 60)
			if err != nil {
				t.Fatal(err)
			}
			wantInstalled := mode == "late-success" || mode == "transport-recovery"
			if wantInstalled {
				if executed != 1 || c.signCalls != 2 || extensions.Load() < 3 {
					t.Fatalf("executed=%d sign calls=%d extensions=%d", executed, c.signCalls, extensions.Load())
				}
				if !bytes.Equal(c.signed[0], c.signed[1]) {
					t.Fatal("retry changed the original CSR")
				}
				root, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := root.Close(); err != nil {
						t.Error(err)
					}
				}()
				cert, err := root.ReadFile("cert.pem")
				if err != nil {
					t.Fatal(err)
				}
				key, err := root.ReadFile("key.pem")
				if err != nil {
					t.Fatal(err)
				}
				defer secret.Wipe(key)
				if err := crypto.VerifyCertKeyMatchPEM(cert, key); err != nil {
					t.Fatal("installed certificate does not match retained host key:", err)
				}
				if len(c.reports) != 1 || c.reports[0].outcome != relay.OutcomeExecuted {
					t.Fatal("late recovery did not report exactly one completed deployment")
				}
			} else {
				if executed != 0 || c.signCalls != 1 {
					t.Fatalf("refusal/cancellation executed=%d sign calls=%d", executed, c.signCalls)
				}
				for _, path := range []string{certPath, keyPath} {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("lost authority wrote host material")
					}
				}
			}
		})
	}
}

func (c *pendingCSRChannel) ExtendJobClaim(context.Context, int64, int) (time.Time, error) {
	c.extensions++
	return time.Now().Add(time.Minute), nil
}

func (c *pendingCSRChannel) SignJobCSR(_ context.Context, _ int64, _ int, csr []byte) ([]byte, []byte, string, error) {
	c.signCalls++
	c.signed = append(c.signed, bytes.Clone(csr))
	if c.signCalls == 1 {
		pending, err := status.New(codes.Unavailable, "certificate issuance is pending").WithDetails(
			&errdetails.ErrorInfo{Domain: "trstctl.agent", Reason: "CERTIFICATE_ISSUANCE_PENDING"},
			&errdetails.RetryInfo{RetryDelay: durationpb.New(10 * time.Millisecond)})
		if err != nil {
			panic(err)
		}
		return nil, nil, "", pending.Err()
	}
	return nil, nil, "", errors.New("fixture terminal signing refusal")
}

func TestPendingHostCSRRetainsTheSameRequestAndClaimUntilTerminalResult(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	c := &pendingCSRChannel{}
	c.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector: "nginx", Target: "pending-host", SubjectCommonName: "pending.example.test",
		TargetConfig: renewTargetConfig(t, certPath, keyPath),
	})}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	executed, err := relay.RunOnceWithHost(ctx, c, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 1, 60)
	if err != nil || executed != 0 {
		t.Fatalf("terminal refusal executed a deployment: executed=%d err=%v", executed, err)
	}
	if c.signCalls != 2 {
		t.Fatalf("pending request was abandoned: signing calls=%d, want pending then terminal result on the same claim", c.signCalls)
	}
	if !bytes.Equal(c.signed[0], c.signed[1]) || len(c.signed[0]) == 0 {
		t.Fatal("pending retry generated a different CSR or key")
	}
	if c.extensions == 0 {
		t.Fatal("pending request was retried without maintaining its exact claim")
	}
	if len(c.reports) != 1 || c.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("pending was reported as a terminal attempt: reports=%d", len(c.reports))
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused signing wrote material: %s", path)
		}
	}
}
