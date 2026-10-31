// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
	"trstctl.com/trstctl/internal/store"
)

// A154: the hmac-dynamic MDM SCEP challenge on the served SCEP endpoint. An MDM
// that speaks the dynamic challenge page (Jamf Pro's "Dynamic-Microsoft CA"
// SCEP payload type) fetches one challenge per device from
// /scep/mscep_admin/{policy} with the policy's username and password; the
// device presents it in its SCEP challengePassword; the gate verifies it
// against the policy named in it and consumes it once in the durable fence.

const (
	mdmSCEPChallengeBucket   = "mdm-scep-challenge"
	mdmSCEPChallengeCapacity = 120.0
	mdmSCEPChallengeRefill   = 2.0 // tokens per second
)

// mdmSCEPDynamicPolicy loads one enabled hmac-dynamic policy of the tenant and
// opens its challenge credential. The caller wipes the returned credential.
func (s *Server) mdmSCEPDynamicPolicy(ctx context.Context, tenantID, policyID string, keyWrapper sealKeyWrapper) (mdmchallenge.DynamicPolicy, error) {
	if _, err := uuid.Parse(policyID); err != nil || s.store == nil || keyWrapper == nil {
		return mdmchallenge.DynamicPolicy{}, mdmchallenge.ErrDynamicChallengePolicy
	}
	policy, err := s.store.GetMDMSCEPPolicy(ctx, tenantID, policyID)
	if errors.Is(err, store.ErrMDMSCEPPolicyNotFound) {
		return mdmchallenge.DynamicPolicy{}, mdmchallenge.ErrDynamicChallengePolicy
	}
	if err != nil {
		return mdmchallenge.DynamicPolicy{}, err
	}
	if !policy.Enabled || policy.ChallengeMode != "hmac-dynamic" || policy.ChallengeCredentialRef == "" {
		return mdmchallenge.DynamicPolicy{}, mdmchallenge.ErrDynamicChallengePolicy
	}
	credential, err := s.openMDMSCEPSecretRef(ctx, tenantID, "challenge credential", policy.ChallengeCredentialRef, keyWrapper)
	if err != nil {
		return mdmchallenge.DynamicPolicy{}, err
	}
	return mdmchallenge.DynamicPolicy{PolicyID: policy.ID, SCEPProfile: policy.SCEPProfile, RotationVersion: policy.RotationVersion, Credential: credential}, nil
}

// openMDMSCEPSecretRef opens one secret:// reference of an MDM SCEP policy from
// the tenant secret store. The caller wipes the plaintext.
func (s *Server) openMDMSCEPSecretRef(ctx context.Context, tenantID, label, ref string, keyWrapper sealKeyWrapper) ([]byte, error) {
	if keyWrapper == nil {
		return nil, fmt.Errorf("server: MDM SCEP %s references require a credential KEK", label)
	}
	name, ok := strings.CutPrefix(strings.TrimSpace(ref), "secret://")
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	if !ok || name == "" {
		return nil, fmt.Errorf("server: MDM SCEP %s must be a non-empty secret:// reference", label)
	}
	rec, err := s.store.GetSecret(ctx, tenantID, name)
	if err != nil {
		return nil, fmt.Errorf("server: MDM SCEP %s is not readable", label)
	}
	plain, err := openTenantValue(ctx, s.tenantCrypto, keyWrapper, tenantID, rec.Sealed, secretStoreAADForMDMSCEP(tenantID, name))
	if err != nil {
		return nil, fmt.Errorf("server: MDM SCEP %s is not openable", label)
	}
	return plain, nil
}

// mdmSCEPChallengePage serves the per-device challenge page. It answers only
// for enabled hmac-dynamic policies of the served SCEP tenant, only to the
// policy's credential, and within a per-tenant rate.
func (s *Server) mdmSCEPChallengePage(tenantID string, keyWrapper sealKeyWrapper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx := r.Context()
		username, password, ok := r.BasicAuth()
		if !ok {
			mdmSCEPChallengeUnauthorized(w)
			return
		}
		if s.store != nil {
			allowed, retryAfter, err := s.store.RateLimitTake(ctx, tenantID, mdmSCEPChallengeBucket, mdmSCEPChallengeCapacity, mdmSCEPChallengeRefill)
			if err != nil {
				http.Error(w, "challenge service unavailable", http.StatusServiceUnavailable)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
				http.Error(w, "too many challenge requests", http.StatusTooManyRequests)
				return
			}
		}
		policy, err := s.mdmSCEPDynamicPolicy(ctx, tenantID, r.PathValue("policy"), keyWrapper)
		if errors.Is(err, mdmchallenge.ErrDynamicChallengePolicy) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			if s.logger != nil {
				s.logger.WarnContext(ctx, "mdm scep challenge page: policy credential unavailable", "error", err)
			}
			http.Error(w, "challenge service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer secret.Wipe(policy.Credential)
		presented := []byte(username + ":" + password)
		defer secret.Wipe(presented)
		if !crypto.ConstantTimeEqual(crypto.SHA256Sum(presented), crypto.SHA256Sum(policy.Credential)) {
			mdmSCEPChallengeUnauthorized(w)
			return
		}
		token, _, err := mdmchallenge.IssueDynamic(tenantID, policy, time.Now())
		if err != nil {
			http.Error(w, "challenge service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The page shape MDMs already parse: the challenge between <B> and </B>
		// after "The enrollment challenge password is:".
		_, _ = fmt.Fprintf(w, "<HTML><Body><P> The enrollment challenge password is: <B> %s </B> <P> This password can be used only once and will expire within 60 minutes. </Body></HTML>\n", html.EscapeString(token))
	})
}

func mdmSCEPChallengeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="trstctl SCEP challenge", charset="UTF-8"`)
	http.Error(w, "the MDM challenge credential is required", http.StatusUnauthorized)
}
