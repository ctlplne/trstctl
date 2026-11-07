// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"context"
	"errors"
	"runtime"
	"slices"
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

func (r relayChannel) localAccountRotationIdentity(ctx context.Context, i hostaccounts.RotationIntent) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if i.Validate() != nil || r.pending == nil || r.id == nil {
		return errors.New("agent: exact native rotation authority, enrollment and durable state are required")
	}
	id := r.id()
	if id == nil || id.TenantID() != i.TenantID || sshtrustrollout.EnrolledAgentID(id.TenantID(), id.CommonName()) != i.AgentID || !slices.Contains(id.Roles(), mtls.AgentRoleHost) {
		return errors.New("agent: native rotation differs from current enrolled host identity")
	}
	return nil
}
func (r relayChannel) AuthorizeLocalAccountRotation(ctx context.Context, i hostaccounts.RotationIntent) error {
	if e := r.localAccountRotationIdentity(ctx, i); e != nil {
		return e
	}
	if runtime.GOOS != "windows" {
		return winaccounts.ErrUnsupported
	}
	return nil
}
func localAccountCredentialResponse(response *transport.RedeemJobCredentialResponse, now time.Time) (map[string][]byte, time.Time, error) {
	if response == nil {
		return nil, time.Time{}, errors.New("agent: empty native rotation redemption")
	}
	expires := time.Unix(response.ExpiresUnix, 0)
	if !expires.After(now) {
		wipeRedeemedItems(response.Items)
		return nil, time.Time{}, errors.New("agent: native rotation credential authorization expired")
	}
	material, e := redeemedItemMap(response.Items)
	if e != nil {
		return nil, time.Time{}, e
	}
	if len(material) != 2 || len(material[hostaccounts.RotationOldCredentialName]) == 0 || len(material[hostaccounts.RotationNewCredentialName]) == 0 {
		wipeRedeemedItems(response.Items)
		return nil, time.Time{}, errors.New("agent: exact native rotation material required")
	}
	return material, expires, nil
}
func (r relayChannel) RedeemLocalAccountRotationCredential(ctx context.Context, job int64, attempt int, i hostaccounts.RotationIntent) (map[string][]byte, time.Time, error) {
	if e := r.AuthorizeLocalAccountRotation(ctx, i); e != nil {
		return nil, time.Time{}, e
	}
	response, e := r.c.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job, Attempt: attempt})
	if e != nil {
		if response != nil {
			wipeRedeemedItems(response.Items)
		}
		return nil, time.Time{}, e
	}
	return localAccountCredentialResponse(response, r.clock())
}
func (r relayChannel) ReplayLocalAccountRotation(ctx context.Context, job int64, i hostaccounts.RotationIntent) (winaccounts.RotationProof, bool, error) {
	if e := r.localAccountRotationIdentity(ctx, i); e != nil {
		return winaccounts.RotationProof{}, false, e
	}
	return r.pending.ReplayLocalAccountRotation(ctx, job, i.Native, i.RotationID, i.PredecessorGenerationID)
}
func (r relayChannel) ExecuteLocalAccountRotation(ctx context.Context, job int64, i hostaccounts.RotationIntent, old, next []byte) (winaccounts.RotationProof, error) {
	if e := r.AuthorizeLocalAccountRotation(ctx, i); e != nil {
		return winaccounts.RotationProof{}, e
	}
	return r.pending.ExecuteLocalAccountRotationOnce(ctx, job, i.Native, i.RotationID, i.PredecessorGenerationID, old, next, winaccounts.NewRotator())
}
func (r relayChannel) ReportLocalAccountRotation(ctx context.Context, job int64, attempt int, i hostaccounts.RotationIntent, result hostaccounts.RotationReport) (bool, error) {
	if e := r.localAccountRotationIdentity(ctx, i); e != nil {
		return false, e
	}
	if job <= 0 || attempt <= 0 {
		return false, errors.New("agent: exact native rotation delivery attempt required")
	}
	raw, e := hostaccounts.MarshalRotationReport(i, result)
	if e != nil {
		return false, e
	}
	value := reportstate.Observation{JobID: job, Attempt: attempt, Outcome: transport.JobOutcomeFailed, Detail: raw, EvidenceDigest: crypto.SHA256Hex(raw)}
	defer value.Destroy()
	if result.Status == "succeeded" {
		value.Outcome = transport.JobOutcomeVerified
		value.LocalAccountRotation = result.Proof
	}
	return r.retainAndSendReport(ctx, value)
}

var _ relay.LocalAccountRotationChannel = relayChannel{}
