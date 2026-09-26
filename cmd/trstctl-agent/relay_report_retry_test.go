// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

type receiptRetryChannelServer struct {
	blockedJobChannel
	report func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error)
	claim  func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error)
}

func (s *receiptRetryChannelServer) ClaimJobs(ctx context.Context, req *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
	if s.claim != nil {
		return s.claim(ctx, req)
	}
	return s.blockedJobChannel.ClaimJobs(ctx, req)
}

func (s *receiptRetryChannelServer) ReportJobResult(ctx context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
	return s.report(ctx, req)
}

func newReceiptRetryChannel(t *testing.T, report func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error), configure ...func(*receiptRetryChannelServer)) relayChannel {
	t.Helper()
	ca, err := mtls.NewCA("receipt-retry-ca")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("receipt-retry-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Destroy)
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "receipt-retry-tenant", []string{mtls.AgentRoleHost}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	serverCreds, err := ca.ServerCredentials([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := &receiptRetryChannelServer{report: report}
	for _, apply := range configure {
		apply(service)
	}
	server := transport.NewServer(serverCreds, service)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	creds, err := mtls.AgentClientCredentials(id, ca.BundlePEM(), "agent.trstctl.local", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(listener.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return relayChannel{c: transport.NewAgentClient(conn), id: func() *mtls.AgentIdentity { return id }}
}

func TestRelayTrustWriteSurvivesReportingFailureWithoutReexecution(t *testing.T) {
	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fixture.Close() }()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der, err := crypto.SelfSignedCACert(key, "Owned reporting recovery anchor", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intent := relay.TrustDistributionIntent{RunID: "reporting-recovery", WaveID: "one", IdentityID: "owned-anchor", Operation: relay.TrustInstall,
		AnchorPath: filepath.Join(root, "root.pem"), AnchorPEM: crypto.EncodeCertificatePEM(der), AnchorFingerprint: crypto.SHA256Hex(der)}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var claims, reports atomic.Int32
	var mu sync.Mutex
	var firstFile os.FileInfo
	ch := newReceiptRetryChannel(t, func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		actual, readErr := fixture.ReadFile("root.pem")
		if readErr != nil || !bytes.Equal(actual, intent.AnchorPEM) {
			t.Errorf("report preceded verified trust installation: %v", readErr)
		}
		info, statErr := fixture.Stat("root.pem")
		if statErr != nil {
			return nil, statErr
		}
		mu.Lock()
		if firstFile == nil {
			firstFile = info
		} else if !os.SameFile(firstFile, info) || !firstFile.ModTime().Equal(info.ModTime()) {
			t.Error("reporting retry rewrote the installed trust anchor")
		}
		mu.Unlock()
		if req.JobID != 78 || req.Attempt != 4 || req.Outcome != transport.JobOutcomeExecuted || req.EvidenceDigest == "" {
			t.Errorf("trust result lost its original attempt or evidence: job=%d attempt=%d outcome=%s", req.JobID, req.Attempt, req.Outcome)
		}
		if reports.Add(1) < 3 {
			return nil, status.Error(codes.Unavailable, "owned transient receipt storage failure")
		}
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	}, func(s *receiptRetryChannelServer) {
		s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			claims.Add(1)
			return &transport.ClaimJobsResponse{Jobs: []transport.ClaimedJob{{JobID: 78, Attempt: 4, Kind: relay.KindTrustDistribute, Payload: payload}}}, nil
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	executed, err := relay.RunOnceWithHost(ctx, ch, nil, connector.LocalOpsConfig{AllowedRoots: []string{root}}, 1, 60)
	if err != nil || executed != 1 || claims.Load() != 1 || reports.Load() != 3 {
		t.Fatalf("trust reporting recovery: executed=%d claims=%d reports=%d err=%v", executed, claims.Load(), reports.Load(), err)
	}
}

func TestRelayRetriesIdenticalSignedTerminalReport(t *testing.T) {
	for _, withCustody := range []bool{false, true} {
		name := "ordinary"
		if withCustody {
			name = "custody"
		}
		t.Run(name, func(t *testing.T) {
			var calls, signatures atomic.Int32
			var mu sync.Mutex
			var original []byte
			ch := newReceiptRetryChannel(t, func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
				encoded, err := json.Marshal(req)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				if original == nil {
					original = encoded
				} else if !bytes.Equal(original, encoded) {
					t.Error("retry changed signed request bytes")
				}
				mu.Unlock()
				if len(req.Signature) == 0 || req.JobID != 71 || req.Attempt != 3 {
					t.Error("report lost its signed attempt binding")
				}
				if withCustody && (req.Custody == nil || req.Custody.GeneratedBy != "receipt-retry-agent") {
					t.Error("retry lost custody binding")
				}
				if calls.Add(1) < 3 {
					return nil, status.Error(codes.Unavailable, "owned transient receipt storage failure")
				}
				return &transport.ReportJobResultResponse{Accepted: true}, nil
			})
			ch.now = func() time.Time { signatures.Add(1); return time.Now() }
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var accepted bool
			var err error
			if withCustody {
				accepted, err = ch.ReportJobResultWithCustody(ctx, 71, 3, transport.JobOutcomeVerified, "owned result", "", strings.Repeat("a", 64), custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable})
			} else {
				accepted, err = ch.ReportJobResult(ctx, 71, 3, transport.JobOutcomeFailed, "owned result", "")
			}
			if err != nil || !accepted || calls.Load() != 3 {
				t.Fatalf("automatic reporting recovery: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
			}
			if signatures.Load() != 1 {
				t.Fatalf("report was re-signed %d times", signatures.Load())
			}
		})
	}
}

func TestRelayTerminalReportRetryStopsOnRefusalAndCancellation(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition, codes.Internal, codes.OK} {
		t.Run(code.String(), func(t *testing.T) {
			var calls atomic.Int32
			ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
				calls.Add(1)
				if code == codes.OK {
					return &transport.ReportJobResultResponse{Accepted: false}, nil
				}
				return nil, status.Error(code, "owned permanent refusal")
			})
			accepted, err := ch.ReportJobResult(t.Context(), 72, 1, transport.JobOutcomeFailed, "owned result", "")
			if accepted || calls.Load() != 1 || status.Code(err) != code {
				t.Fatalf("refusal retried: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
			}
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var calls atomic.Int32
		ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
			calls.Add(1)
			cancel()
			return nil, status.Error(codes.Unavailable, "owned temporary failure")
		})
		accepted, err := ch.ReportJobResult(ctx, 73, 1, transport.JobOutcomeFailed, "owned result", "")
		if accepted || (!errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled) || calls.Load() != 1 {
			t.Fatalf("canceled retry: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
		}
	})
}

func TestRelayTerminalReportRecoveryIsBounded(t *testing.T) {
	t.Run("temporary failures stop without busy polling", func(t *testing.T) {
		var calls atomic.Int32
		ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
			calls.Add(1)
			return nil, status.Error(codes.Unavailable, "owned persistent channel failure")
		})
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		start := time.Now()
		accepted, err := ch.ReportJobResult(ctx, 74, 2, transport.JobOutcomeExecuted, "owned result", "")
		if accepted || calls.Load() != 6 || status.Code(err) != codes.Unavailable {
			t.Fatalf("unbounded or premature recovery: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
		}
		if time.Since(start) < 3*time.Second || ctx.Err() != nil {
			t.Fatalf("retry did not back off or exhausted caller deadline: elapsed=%v context=%v", time.Since(start), ctx.Err())
		}
	})
	t.Run("stalled RPC has a deadline and can recover", func(t *testing.T) {
		var calls atomic.Int32
		ch := newReceiptRetryChannel(t, func(ctx context.Context, _ *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
			if calls.Add(1) == 1 {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 11*time.Second {
					t.Error("terminal-report RPC has no bounded deadline")
					return nil, status.Error(codes.Internal, "missing RPC deadline")
				}
				<-ctx.Done()
				return nil, status.FromContextError(ctx.Err()).Err()
			}
			return &transport.ReportJobResultResponse{Accepted: true}, nil
		})
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		accepted, err := ch.ReportJobResult(ctx, 75, 2, transport.JobOutcomeVerifyFailed, "owned result", "")
		if !accepted || err != nil || calls.Load() != 2 {
			t.Fatalf("stalled-report recovery: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
		}
	})
	t.Run("backpressure can recover", func(t *testing.T) {
		var calls atomic.Int32
		ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
			if calls.Add(1) == 1 {
				return nil, status.Error(codes.ResourceExhausted, "owned temporary capacity failure")
			}
			return &transport.ReportJobResultResponse{Accepted: true}, nil
		})
		accepted, err := ch.ReportJobResult(t.Context(), 76, 2, transport.JobOutcomeVerified, "owned result", "")
		if !accepted || err != nil || calls.Load() != 2 {
			t.Fatalf("backpressure recovery: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
		}
	})
	t.Run("rollback authorization is not a terminal observation", func(t *testing.T) {
		var calls atomic.Int32
		ch := newReceiptRetryChannel(t, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
			calls.Add(1)
			return nil, status.Error(codes.Unavailable, "owned unavailable authority")
		})
		accepted, err := ch.ReportJobResult(t.Context(), 77, 2, transport.JobOutcomeAuthorizeRollback, "", "")
		if accepted || status.Code(err) != codes.Unavailable || calls.Load() != 1 {
			t.Fatalf("authorization retried: accepted=%v calls=%d err=%v", accepted, calls.Load(), err)
		}
	})
}
