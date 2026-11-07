// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/grpc/peer"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

const localRotationTenant = "58920000-0000-4000-8000-000000000001"

func channelRotationIntent(t *testing.T, ch relayChannel) hostaccounts.RotationIntent {
	t.Helper()
	id := ch.id()
	i, e := hostaccounts.NewRotationIntent(hostaccounts.RotationIntent{RotationID: "58920000-0000-4000-8000-000000000002", AccountID: "58920000-0000-4000-8000-000000000003", InventoryRunID: "58920000-0000-4000-8000-000000000004", TenantID: id.TenantID(), AgentID: sshtrustrollout.EnrolledAgentID(id.TenantID(), id.CommonName()), Native: winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "Owned Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}})
	if e != nil {
		t.Fatal(e)
	}
	return i
}

type localChannelNativeFixture struct{ calls int }

func (f *localChannelNativeFixture) Rotate(ctx context.Context, b winaccounts.RotationBinding, generation string, _, _ []byte, fence winaccounts.RotationFence) (winaccounts.RotationProof, error) {
	f.calls++
	fresh, e := fence.Begin(ctx, b, generation)
	if e != nil || !fresh {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
	}
	p := winaccounts.RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
	if e = fence.Complete(ctx, p); e != nil {
		return winaccounts.RotationProof{}, e
	}
	return p, nil
}
func TestLocalAccountRotationReceiptRecoversOriginalProofBeforeClaimsA268(t *testing.T) {
	var permit atomic.Bool
	var claims, reports atomic.Int32
	var intent hostaccounts.RotationIntent
	var original []byte
	ch := newReceiptRetryChannelForTenant(t, localRotationTenant, func(ctx context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			t.Error("native receipt has no authenticated peer")
			return nil, errors.New("no peer")
		}
		info, e := mtls.PeerCertInfoFromAuthInfo(p.AuthInfo)
		if e != nil {
			t.Error(e)
			return nil, e
		}
		r, e := hostaccounts.DecodeRotationReport([]byte(req.Detail))
		if e != nil || r.Validate(intent) != nil || req.Outcome != transport.JobOutcomeVerified || req.JobID != 589 || req.Attempt != 1 || req.EvidenceDigest != crypto.SHA256Hex([]byte(req.Detail)) {
			t.Error("native report lost exact original facts", e)
			return nil, errors.New("wrong native report")
		}
		statement := transport.JobReceiptStatement{TenantID: info.TenantID, AgentCommonName: info.CommonName, JobID: req.JobID, Attempt: req.Attempt, Outcome: req.Outcome, EvidenceDigest: req.EvidenceDigest, DetailDigest: transport.DetailDigest(req.Detail), IssuedAtUnix: req.IssuedAtUnix}
		if e = mtls.VerifyStatement(info.LeafDER, statement.Canonical(), req.Signature); e != nil {
			t.Error(e)
			return nil, e
		}
		if !bytes.Equal(original, []byte(req.Detail)) {
			t.Error("receipt retry replaced native observation timestamp or proof")
		}
		reports.Add(1)
		return &transport.ReportJobResultResponse{Accepted: permit.Load()}, nil
	}, func(s *receiptRetryChannelServer) {
		s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
			claims.Add(1)
			return &transport.ClaimJobsResponse{}, nil
		}
	})
	intent = channelRotationIntent(t, ch)
	root := t.TempDir()
	s, e := reportstate.Open(root, "owned enrolled host")
	if e != nil {
		t.Fatal(e)
	}
	ch.pending = s
	t.Cleanup(func() { _ = s.Close() })
	native := &localChannelNativeFixture{}
	p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 589, intent.Native, intent.RotationID, "", nil, nil, native)
	if e != nil {
		t.Fatal(e)
	}
	r := hostaccounts.RotationReport{RotationID: intent.RotationID, BindingDigest: intent.BindingDigest, Status: "succeeded", ObservedAt: p.ObservedAt, Proof: &p}
	original, e = hostaccounts.MarshalRotationReport(intent, r)
	if e != nil {
		t.Fatal(e)
	}
	if accepted, e := ch.ReportLocalAccountRotation(t.Context(), 589, 1, intent, r); e != nil || accepted {
		t.Fatal("first receipt should remain durable", e)
	}
	if _, e = ch.ClaimJobs(t.Context(), []string{hostaccounts.RotationDestination}, 1, 60); e == nil || claims.Load() != 0 {
		t.Fatal("new claim bypassed unaccepted native receipt")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = reportstate.Open(root, "owned enrolled host")
	if e != nil {
		t.Fatal(e)
	}
	ch.pending = s
	permit.Store(true)
	if _, e = ch.ClaimJobs(t.Context(), []string{hostaccounts.RotationDestination}, 1, 60); e != nil || claims.Load() != 1 || reports.Load() != 3 || native.calls != 1 {
		t.Fatal("native receipt recovery did not resume exactly once", e)
	}
	next := intent
	next.RotationID = "58920000-0000-4000-8000-000000000005"
	next.PredecessorGenerationID = intent.RotationID
	next, e = hostaccounts.NewRotationIntent(next)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 2, next.Native, next.RotationID, next.PredecessorGenerationID, nil, nil, native); e != nil || native.calls != 2 {
		t.Fatal("accepted wire report did not durably acknowledge its native generation", e)
	}
	t.Log("A268_HOST_ROTATION_RECEIPT_OK: real mTLS, independently verified detached receipts, durable original replay and exact journal acknowledgement; native effect is a separate fixture")
}
func TestLocalAccountRotationChannelUsesCurrentEnrollmentAndDurableStateA268(t *testing.T) {
	ch := newReceiptRetryChannelForTenant(t, localRotationTenant, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		t.Error("authority preflight unexpectedly reported")
		return nil, errors.New("unexpected network")
	})
	i := channelRotationIntent(t, ch)
	if e := ch.localAccountRotationIdentity(t.Context(), i); e == nil {
		t.Fatal("missing journal accepted")
	}
	s, e := reportstate.Open(t.TempDir(), "owned host")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	ch.pending = s
	if e = ch.localAccountRotationIdentity(t.Context(), i); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*hostaccounts.RotationIntent){func(v *hostaccounts.RotationIntent) { v.AgentID = v.AccountID }, func(v *hostaccounts.RotationIntent) { v.TenantID = v.AccountID }} {
		v := i
		change(&v)
		v, _ = hostaccounts.NewRotationIntent(v)
		if ch.localAccountRotationIdentity(t.Context(), v) == nil {
			t.Fatal("job-supplied identity overrode current certificate")
		}
	}
	if runtime.GOOS != "windows" && !errors.Is(ch.AuthorizeLocalAccountRotation(t.Context(), i), winaccounts.ErrUnsupported) {
		t.Fatal("non-Windows process authorized native password redemption")
	}
	ch.id = nil
	if ch.localAccountRotationIdentity(t.Context(), i) == nil {
		t.Fatal("missing enrolled identity authorized password work")
	}
}
func TestLocalAccountRotationReportRejectsProofAbsentFromJournalA268(t *testing.T) {
	var sent atomic.Int32
	ch := newReceiptRetryChannelForTenant(t, localRotationTenant, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
		sent.Add(1)
		return &transport.ReportJobResultResponse{Accepted: true}, nil
	})
	i := channelRotationIntent(t, ch)
	s, e := reportstate.Open(t.TempDir(), "owned host")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	ch.pending = s
	p := winaccounts.RotationProof{Binding: i.Native, GenerationID: i.RotationID, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
	r := hostaccounts.RotationReport{RotationID: i.RotationID, BindingDigest: i.BindingDigest, Status: "succeeded", ObservedAt: p.ObservedAt, Proof: &p}
	if accepted, e := ch.ReportLocalAccountRotation(t.Context(), 589, 1, i, r); e == nil || accepted || sent.Load() != 0 {
		t.Fatal("forged completion left host journal as accepted")
	}
	raw, _ := json.Marshal(r)
	if bytes.Contains(raw, []byte("password\"")) {
		t.Fatal("public proof unexpectedly contains a password field")
	}
}

func TestLocalAccountRotationCredentialEnvelopeRejectsDuplicateOrEmptyNamesA268(t *testing.T) {
	for _, kind := range []string{"duplicate", "empty"} {
		t.Run(kind, func(t *testing.T) {
			ch := newReceiptRetryChannelForTenant(t, localRotationTenant, func(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
				t.Error("redemption test reported an effect")
				return nil, errors.New("unexpected report")
			}, func(s *receiptRetryChannelServer) {
				s.redeem = func(context.Context, *transport.RedeemJobCredentialRequest) (*transport.RedeemJobCredentialResponse, error) {
					first := transport.RedeemedSecret{Name: hostaccounts.RotationOldCredentialName, Value: bytes.Repeat([]byte{'x'}, 32)}
					second := transport.RedeemedSecret{Name: hostaccounts.RotationNewCredentialName, Value: bytes.Repeat([]byte{'z'}, 32)}
					if kind == "empty" {
						first.Name = ""
						return &transport.RedeemJobCredentialResponse{Items: []transport.RedeemedSecret{first, second}}, nil
					}
					return &transport.RedeemJobCredentialResponse{Items: []transport.RedeemedSecret{first, second, first}}, nil
				}
			})
			if material, e := ch.RedeemJobCredential(t.Context(), 589, 1); e == nil || material != nil {
				t.Fatal("ambiguous secret envelope silently overwrote credential bytes")
			}
		})
	}
}

func TestLocalAccountRotationCredentialExpiryAndWipeOwnershipA268(t *testing.T) {
	now := time.Now()
	for _, kind := range []string{"expired", "duplicate", "empty", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			items := []transport.RedeemedSecret{{Name: hostaccounts.RotationOldCredentialName, Value: bytes.Repeat([]byte{'x'}, 32)}, {Name: hostaccounts.RotationNewCredentialName, Value: bytes.Repeat([]byte{'z'}, 32)}}
			expires := now.Add(time.Minute).Unix()
			switch kind {
			case "expired":
				expires = now.Add(-time.Second).Unix()
			case "duplicate":
				items = append(items, transport.RedeemedSecret{Name: items[0].Name, Value: bytes.Repeat([]byte{'q'}, 32)})
			case "empty":
				items[0].Name = ""
			case "foreign":
				items[0].Name = "secret://unrelated"
			}
			values, _, e := localAccountCredentialResponse(&transport.RedeemJobCredentialResponse{ExpiresUnix: expires, Items: items}, now)
			if e == nil || values != nil {
				t.Fatal("invalid native material authorization accepted")
			}
			for _, item := range items {
				if !bytes.Equal(item.Value, make([]byte, len(item.Value))) {
					t.Fatal("refused secret wire buffer lost its wipe owner")
				}
			}
		})
	}
}

func TestLocalAccountRotationLiveMaterialTransfersIntoLockedOwnershipA268(t *testing.T) {
	now := time.Now()
	response := &transport.RedeemJobCredentialResponse{ExpiresUnix: now.Add(time.Minute).Unix(), Items: []transport.RedeemedSecret{{Name: hostaccounts.RotationOldCredentialName, Value: bytes.Repeat([]byte{'x'}, 32)}, {Name: hostaccounts.RotationNewCredentialName, Value: bytes.Repeat([]byte{'z'}, 32)}}}
	values, expires, e := localAccountCredentialResponse(response, now)
	if e != nil || len(values) != 2 || !expires.Equal(time.Unix(response.ExpiresUnix, 0)) {
		t.Fatal("live exact private material was not transferred", e)
	}
	locked, destroy, e := relay.AdoptMaterial(values)
	if e != nil {
		t.Fatal(e)
	}
	defer destroy()
	if len(locked[hostaccounts.RotationOldCredentialName]) != 32 || len(locked[hostaccounts.RotationNewCredentialName]) != 32 {
		t.Fatal("locked native material changed")
	}
	for _, item := range response.Items {
		if !bytes.Equal(item.Value, make([]byte, len(item.Value))) {
			t.Fatal("wire private material survived locked adoption")
		}
	}
}
