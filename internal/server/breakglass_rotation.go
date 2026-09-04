// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type breakglassVerifier struct {
	caDER     []byte
	publicDER []byte
}

type breakglassRotationEvent struct {
	PreviousSignerHandle   string   `json:"previous_signer_handle"`
	ActiveSignerHandle     string   `json:"active_signer_handle"`
	PreviousCertificateDER []byte   `json:"previous_certificate_der"`
	ActiveCertificateDER   []byte   `json:"active_certificate_der"`
	NewSignedByPreviousDER []byte   `json:"new_signed_by_previous_der"`
	PreviousSignedByNewDER []byte   `json:"previous_signed_by_new_der"`
	CeremonyID             string   `json:"ceremony_id"`
	RequestDigest          string   `json:"request_digest"`
	Reason                 string   `json:"reason"`
	TTLSeconds             int64    `json:"ttl_seconds"`
	Approvers              []string `json:"approvers"`
}

type breakglassIssuedEvent struct {
	RequestID     string            `json:"request_id"`
	Subject       string            `json:"subject"`
	Reason        string            `json:"reason"`
	IssuedAt      time.Time         `json:"issued_at"`
	Approvals     int               `json:"approvals"`
	Bundle        breakglass.Bundle `json:"bundle"`
	CeremonyID    string            `json:"ceremony_id"`
	RequestDigest string            `json:"request_digest"`
}

type breakglassCrossSignEvent struct {
	IssuerSignerHandle   string   `json:"issuer_signer_handle"`
	IssuerCertificateDER []byte   `json:"issuer_certificate_der"`
	TargetCertificateDER []byte   `json:"target_certificate_der"`
	CrossCertificateDER  []byte   `json:"cross_certificate_der"`
	CeremonyID           string   `json:"ceremony_id"`
	RequestDigest        string   `json:"request_digest"`
	Approvers            []string `json:"approvers"`
}

// configuredBreakglassRuntime is the production online break-glass authority.
// It owns no private bytes: every signature is made by a persisted,
// purpose-constrained, dual-control RemoteSigner in trstctl-signer.
type configuredBreakglassRuntime struct {
	mu sync.Mutex

	tenantID  string
	threshold int
	operators []string
	store     *store.Store
	log       *events.Log
	provider  SignerProvider
	signAuthz signing.SignTokenProvider
	auditor   auditsink.Auditor

	activeHandle  string
	baseHandle    string
	activeCertDER []byte
	activeSigner  *signing.RemoteSigner
	verifiers     []breakglassVerifier
}

func (r *configuredBreakglassRuntime) BreakglassConfiguration() api.BreakglassConfiguration {
	return api.BreakglassConfiguration{ApprovalThreshold: r.threshold, ConfiguredOperatorCount: len(r.operators)}
}

// breakglassRotationFromConfig is the explicit production assembly seam. It
// binds the configured certificate and public verifier to one persisted signer
// handle, then replays every completed rotation before the routes are exposed.
// Reconciliation-only deployments return nil and never require signer access.
func breakglassRotationFromConfig(ctx context.Context, cfg config.Breakglass, st *store.Store, log *events.Log, provider SignerProvider, signAuthz signing.SignTokenProvider, caCertDER, publicKeyDER []byte) (*configuredBreakglassRuntime, error) {
	if !cfg.OnlineEnabled {
		return nil, nil
	}
	if err := cfg.ValidateEnabled(); err != nil {
		return nil, err
	}
	if st == nil || log == nil || provider == nil || provider.Client() == nil || signAuthz == nil {
		return nil, errors.New("breakglass: online lifecycle requires PostgreSQL, event log, signer, and dual-control authorizer")
	}
	signer, err := provider.Client().SignerForDualControlHandle(ctx, strings.TrimSpace(cfg.SignerHandle), signing.PurposeCASign, signAuthz)
	if err != nil {
		return nil, fmt.Errorf("breakglass: bind persisted signer handle %q: %w", cfg.SignerHandle, err)
	}
	if !bytes.Equal(signer.Public().DER, publicKeyDER) {
		return nil, errors.New("breakglass: configured public key does not match persisted signer handle")
	}
	if err := crypto.VerifyCertificateSigner(caCertDER, signer.Public()); err != nil {
		return nil, fmt.Errorf("breakglass: configured CA/signer mismatch: %w", err)
	}
	operators := compactSortedOperators(cfg.Operators)
	runtime := &configuredBreakglassRuntime{
		tenantID: strings.TrimSpace(cfg.TenantID), threshold: cfg.Threshold, operators: operators,
		store: st, log: log, provider: provider, signAuthz: signAuthz, auditor: audit.NewAuditor(log),
		activeHandle: strings.TrimSpace(cfg.SignerHandle), baseHandle: strings.TrimSpace(cfg.SignerHandle), activeCertDER: append([]byte(nil), caCertDER...),
		activeSigner: signer,
		verifiers:    []breakglassVerifier{{caDER: append([]byte(nil), caCertDER...), publicDER: append([]byte(nil), publicKeyDER...)}},
	}
	if err := runtime.replayRotations(ctx); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *configuredBreakglassRuntime) StartBreakglassIssueCeremony(ctx context.Context, tenantID string, req breakglass.EmergencyRequest, ttl time.Duration) (api.BreakglassCeremony, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return api.BreakglassCeremony{}, err
	}
	return r.startCeremony(ctx, breakglass.IssuePurpose(tenantID, req, ttl))
}

func (r *configuredBreakglassRuntime) StartBreakglassRotationCeremony(ctx context.Context, tenantID string, req api.BreakglassRotationIntent) (api.BreakglassCeremony, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return api.BreakglassCeremony{}, err
	}
	r.mu.Lock()
	purpose := breakglass.RotationPurpose(tenantID, r.activeHandle, r.activeCertDER, strings.TrimSpace(req.Reason), time.Duration(req.TTLSeconds)*time.Second)
	r.mu.Unlock()
	return r.startCeremony(ctx, purpose)
}

func (r *configuredBreakglassRuntime) StartBreakglassCrossSignCeremony(ctx context.Context, tenantID string, targetCertDER []byte) (api.BreakglassCeremony, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return api.BreakglassCeremony{}, err
	}
	r.mu.Lock()
	purpose := breakglass.CrossSignPurpose(tenantID, r.activeHandle, targetCertDER)
	r.mu.Unlock()
	return r.startCeremony(ctx, purpose)
}

func (r *configuredBreakglassRuntime) startCeremony(ctx context.Context, purpose string) (api.BreakglassCeremony, error) {
	opener := ""
	if actor, ok := events.ActorFromContext(ctx); ok {
		opener = actor.Subject
	}
	id := uuid.NewString()
	payload := projections.CACeremonyStarted{CeremonyID: id, Purpose: purpose, Threshold: r.threshold, Opener: opener}
	raw, err := json.Marshal(payload)
	if err != nil {
		return api.BreakglassCeremony{}, err
	}
	event, err := r.log.Append(ctx, events.Event{Type: projections.EventCACeremonyStarted, TenantID: r.tenantID, Data: raw})
	if err != nil {
		return api.BreakglassCeremony{}, err
	}
	if err := projections.New(r.store).Apply(ctx, event); err != nil {
		return api.BreakglassCeremony{}, err
	}
	ceremony, err := r.store.GetKeyCeremony(ctx, r.tenantID, id)
	return breakglassCeremonyResponse(ceremony), err
}

func (r *configuredBreakglassRuntime) IssueBreakglass(ctx context.Context, tenantID string, req breakglass.EmergencyRequest, ttl time.Duration) (breakglass.Bundle, int, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return breakglass.Bundle{}, 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	purpose := breakglass.IssuePurpose(tenantID, req, ttl)
	var bundle breakglass.Bundle
	err := r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		approvers, err := r.consumeAndVerifyCeremony(ctx, tx, req.CeremonyID, purpose)
		if err != nil {
			return err
		}
		svc, err := breakglass.New(breakglass.Config{
			TenantID: tenantID, Quorum: breakglass.Quorum{Threshold: r.threshold, Operators: r.operators},
			CACertDER: r.activeCertDER, CASigner: r.activeSigner,
		})
		if err != nil {
			return err
		}
		req.Approvals = approvers
		bundle, err = svc.IssueOffline(req, ttl)
		if err != nil {
			return err
		}
		candidate := breakglassIssuedEvent{
			RequestID: bundle.RequestID, Subject: bundle.Subject, Reason: bundle.Reason,
			IssuedAt: bundle.IssuedAt, Approvals: len(bundle.Approvals), Bundle: bundle,
			CeremonyID: req.CeremonyID, RequestDigest: strings.TrimPrefix(purpose, "breakglass-issue:"),
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		event, err := r.log.Append(ctx, events.Event{ID: "breakglass-issued-" + req.CeremonyID, Type: projections.EventBreakglassIssued, TenantID: tenantID, Data: data})
		if err != nil {
			return err
		}
		var canonical breakglassIssuedEvent
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.CeremonyID != req.CeremonyID || canonical.RequestDigest != strings.TrimPrefix(purpose, "breakglass-issue:") ||
			canonical.RequestID != req.ID || canonical.Subject != req.Subject || canonical.Reason != req.Reason ||
			canonical.Bundle.RequestID != req.ID || canonical.Bundle.Subject != req.Subject || canonical.Bundle.Reason != req.Reason ||
			!canonical.IssuedAt.Equal(canonical.Bundle.IssuedAt) || canonical.Approvals != len(canonical.Bundle.Approvals) {
			return errors.New("breakglass: canonical issue event does not match the consumed exact request")
		}
		if err := (breakglass.Quorum{Threshold: r.threshold, Operators: r.operators}).Verify(canonical.Bundle.Approvals); err != nil {
			return err
		}
		if err := breakglass.Verify(canonical.Bundle, r.activeCertDER, r.activeSigner.Public().DER); err != nil {
			return err
		}
		bundle = canonical.Bundle
		return projections.New(r.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		return breakglass.Bundle{}, 0, err
	}
	return bundle, 1, nil
}

func (r *configuredBreakglassRuntime) RotateBreakglass(ctx context.Context, tenantID string, req api.BreakglassRotationRequest) (api.BreakglassRotation, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return api.BreakglassRotation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ttl := time.Duration(req.TTLSeconds) * time.Second
	reason := strings.TrimSpace(req.Reason)
	purpose := breakglass.RotationPurpose(tenantID, r.activeHandle, r.activeCertDER, reason, ttl)
	newHandle := r.baseHandle + "-rotation-" + req.CeremonyID
	var canonical breakglassRotationEvent
	var nextSigner *signing.RemoteSigner
	var signerCreated, eventAppended bool
	err := r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		approvers, err := r.consumeAndVerifyCeremony(ctx, tx, req.CeremonyID, purpose)
		if err != nil {
			return err
		}
		nextSigner, signerCreated, err = r.createOrBindRotationSigner(ctx, newHandle)
		if err != nil {
			return err
		}
		profile, err := crypto.HierarchyCAProfileFromCertificate(r.activeCertDER, ttl)
		if err != nil {
			return err
		}
		issued, err := crypto.SelfSignedHierarchyCA(nextSigner, profile)
		if err != nil {
			return err
		}
		newByOld, err := crypto.CrossSignHierarchyCA(r.activeCertDER, r.activeSigner, issued.CertificateDER)
		if err != nil {
			return err
		}
		oldByNew, err := crypto.CrossSignHierarchyCA(issued.CertificateDER, nextSigner, r.activeCertDER)
		if err != nil {
			return err
		}
		candidate := breakglassRotationEvent{
			PreviousSignerHandle: r.activeHandle, ActiveSignerHandle: newHandle,
			PreviousCertificateDER: append([]byte(nil), r.activeCertDER...), ActiveCertificateDER: issued.CertificateDER,
			NewSignedByPreviousDER: newByOld.CertificateDER, PreviousSignedByNewDER: oldByNew.CertificateDER,
			CeremonyID: req.CeremonyID, RequestDigest: strings.TrimPrefix(purpose, "breakglass-rotate:"),
			Reason: reason, TTLSeconds: req.TTLSeconds, Approvers: approvers,
		}
		raw, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		event, err := r.log.Append(ctx, events.Event{ID: "breakglass-rotation-" + req.CeremonyID, Type: projections.EventBreakglassCARotated, TenantID: tenantID, Data: raw})
		if event.ID != "" {
			eventAppended = true
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.CeremonyID != req.CeremonyID || canonical.ActiveSignerHandle != newHandle {
			return errors.New("breakglass: canonical rotation event does not match the consumed ceremony or successor handle")
		}
		if err := r.validateRotationEvent(ctx, canonical, r.activeHandle, r.activeCertDER, nextSigner); err != nil {
			return err
		}
		return projections.New(r.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		if signerCreated && !eventAppended && nextSigner != nil {
			_ = nextSigner.Destroy(ctx)
		}
		return api.BreakglassRotation{}, err
	}
	r.activeHandle = canonical.ActiveSignerHandle
	r.activeCertDER = append([]byte(nil), canonical.ActiveCertificateDER...)
	r.activeSigner = nextSigner
	r.verifiers = append(r.verifiers, breakglassVerifier{caDER: append([]byte(nil), canonical.ActiveCertificateDER...), publicDER: append([]byte(nil), nextSigner.Public().DER...)})
	return rotationAPIResponse(canonical), nil
}

func (r *configuredBreakglassRuntime) CrossSignBreakglass(ctx context.Context, tenantID string, req api.BreakglassCrossSignRequest) (api.BreakglassCrossSign, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return api.BreakglassCrossSign{}, err
	}
	targetDER, err := oneCertificateDER(req.CertificatePEM)
	if err != nil {
		return api.BreakglassCrossSign{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	purpose := breakglass.CrossSignPurpose(tenantID, r.activeHandle, targetDER)
	var canonical breakglassCrossSignEvent
	err = r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		approvers, err := r.consumeAndVerifyCeremony(ctx, tx, req.CeremonyID, purpose)
		if err != nil {
			return err
		}
		issued, err := crypto.CrossSignHierarchyCA(r.activeCertDER, r.activeSigner, targetDER)
		if err != nil {
			return err
		}
		candidate := breakglassCrossSignEvent{
			IssuerSignerHandle: r.activeHandle, IssuerCertificateDER: append([]byte(nil), r.activeCertDER...),
			TargetCertificateDER: targetDER, CrossCertificateDER: issued.CertificateDER,
			CeremonyID: req.CeremonyID, RequestDigest: strings.TrimPrefix(purpose, "breakglass-cross-sign:"), Approvers: approvers,
		}
		raw, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		event, err := r.log.Append(ctx, events.Event{ID: "breakglass-cross-sign-" + req.CeremonyID, Type: projections.EventBreakglassCACrossSigned, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if canonical.CeremonyID != req.CeremonyID || canonical.IssuerSignerHandle != r.activeHandle ||
			!bytes.Equal(canonical.IssuerCertificateDER, r.activeCertDER) || !bytes.Equal(canonical.TargetCertificateDER, targetDER) {
			return errors.New("breakglass: canonical cross-sign event does not match the consumed request")
		}
		if canonical.RequestDigest != strings.TrimPrefix(purpose, "breakglass-cross-sign:") {
			return errors.New("breakglass: canonical cross-sign event has the wrong exact request digest")
		}
		if err := (breakglass.Quorum{Threshold: r.threshold, Operators: r.operators}).Verify(canonical.Approvers); err != nil {
			return err
		}
		if err := crypto.VerifyCrossSignedCA(canonical.IssuerCertificateDER, canonical.TargetCertificateDER, canonical.CrossCertificateDER); err != nil {
			return err
		}
		return projections.New(r.store).ApplyTx(ctx, tx, event)
	})
	if err != nil {
		return api.BreakglassCrossSign{}, err
	}
	return api.BreakglassCrossSign{
		IssuerSignerHandle: canonical.IssuerSignerHandle, TargetSHA256: crypto.SHA256Hex(canonical.TargetCertificateDER),
		CertificatePEM: certificatePEM(canonical.CrossCertificateDER), CeremonyID: canonical.CeremonyID,
	}, nil
}

func (r *configuredBreakglassRuntime) ReconcileBreakglass(ctx context.Context, tenantID string, bundles []breakglass.Bundle) (int, error) {
	if err := r.requireTenant(tenantID); err != nil {
		return 0, err
	}
	r.mu.Lock()
	verifiers := append([]breakglassVerifier(nil), r.verifiers...)
	r.mu.Unlock()
	reconciled := 0
	for _, bundle := range bundles {
		verified := false
		for _, verifier := range verifiers {
			if breakglass.Verify(bundle, verifier.caDER, verifier.publicDER) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return reconciled, fmt.Errorf("%w: bundle %q failed every active/overlap verifier", api.ErrBreakglassInvalidBundle, bundle.RequestID)
		}
		data, err := json.Marshal(map[string]any{
			"request_id": bundle.RequestID, "subject": bundle.Subject, "reason": bundle.Reason,
			"issued_at": bundle.IssuedAt, "approvals": len(bundle.Approvals),
		})
		if err != nil {
			return reconciled, err
		}
		if err := r.auditor.Audit(ctx, "breakglass.issued", tenantID, data); err != nil {
			return reconciled, err
		}
		reconciled++
	}
	return reconciled, nil
}

func (r *configuredBreakglassRuntime) consumeAndVerifyCeremony(ctx context.Context, tx pgx.Tx, ceremonyID, purpose string) ([]string, error) {
	ceremony, evidence, err := r.store.ValidateKeyCeremonyWithApprovalEvidenceTx(ctx, tx, r.tenantID, ceremonyID, purpose)
	if err != nil {
		return nil, err
	}
	if ceremony.Threshold != r.threshold {
		return nil, fmt.Errorf("breakglass: ceremony threshold %d does not match configured threshold %d", ceremony.Threshold, r.threshold)
	}
	expected := make(map[uint64]store.KeyCeremonyApprovalEvidence, len(evidence))
	for _, item := range evidence {
		expected[item.EventSequence] = item
	}
	validated := map[string]bool{}
	if err := r.log.Replay(ctx, 1, func(event events.Event) error {
		item, ok := expected[event.Sequence]
		if !ok {
			return nil
		}
		if event.ID != item.EventID || event.TenantID != r.tenantID || event.Type != projections.EventCACeremonyApproved || event.Actor == nil {
			return errors.New("breakglass: approval row is not bound to an authenticated immutable ceremony event")
		}
		var payload projections.CACeremonyApproved
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.CeremonyID != ceremonyID || payload.Custodian != item.Custodian || event.Actor.Subject != item.Custodian {
			return errors.New("breakglass: approval event actor/custodian/ceremony binding mismatch")
		}
		validated[item.Custodian] = true
		delete(expected, event.Sequence)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(expected) != 0 || len(validated) != len(evidence) {
		return nil, errors.New("breakglass: immutable approval evidence is incomplete")
	}
	approvers := make([]string, 0, len(validated))
	for approver := range validated {
		approvers = append(approvers, approver)
	}
	sort.Strings(approvers)
	if err := (breakglass.Quorum{Threshold: r.threshold, Operators: r.operators}).Verify(approvers); err != nil {
		return nil, err
	}
	return approvers, nil
}

func (r *configuredBreakglassRuntime) replayRotations(ctx context.Context) error {
	return r.log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID != r.tenantID {
			return nil
		}
		if event.Type == projections.EventBreakglassCACrossSigned {
			var payload breakglassCrossSignEvent
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return fmt.Errorf("breakglass: replay cross-sign event %s: %w", event.ID, err)
			}
			if payload.IssuerSignerHandle != r.activeHandle || !bytes.Equal(payload.IssuerCertificateDER, r.activeCertDER) {
				return fmt.Errorf("breakglass: replay cross-sign event %s does not match active authority", event.ID)
			}
			expected := breakglass.CrossSignPurpose(r.tenantID, r.activeHandle, payload.TargetCertificateDER)
			if payload.RequestDigest != strings.TrimPrefix(expected, "breakglass-cross-sign:") {
				return fmt.Errorf("breakglass: replay cross-sign event %s has the wrong request digest", event.ID)
			}
			if err := (breakglass.Quorum{Threshold: r.threshold, Operators: r.operators}).Verify(payload.Approvers); err != nil {
				return fmt.Errorf("breakglass: replay cross-sign event %s approvers: %w", event.ID, err)
			}
			return crypto.VerifyCrossSignedCA(payload.IssuerCertificateDER, payload.TargetCertificateDER, payload.CrossCertificateDER)
		}
		if event.Type != projections.EventBreakglassCARotated {
			return nil
		}
		var payload breakglassRotationEvent
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return fmt.Errorf("breakglass: replay rotation event %s: %w", event.ID, err)
		}
		signer, err := r.provider.Client().SignerForDualControlHandle(ctx, payload.ActiveSignerHandle, signing.PurposeCASign, r.signAuthz)
		if err != nil {
			return fmt.Errorf("breakglass: replay bind signer %q: %w", payload.ActiveSignerHandle, err)
		}
		if err := r.validateRotationEvent(ctx, payload, r.activeHandle, r.activeCertDER, signer); err != nil {
			return fmt.Errorf("breakglass: replay rotation %s: %w", event.ID, err)
		}
		r.activeHandle = payload.ActiveSignerHandle
		r.activeCertDER = append([]byte(nil), payload.ActiveCertificateDER...)
		r.activeSigner = signer
		r.verifiers = append(r.verifiers, breakglassVerifier{caDER: append([]byte(nil), payload.ActiveCertificateDER...), publicDER: append([]byte(nil), signer.Public().DER...)})
		return nil
	})
}

func (r *configuredBreakglassRuntime) validateRotationEvent(_ context.Context, payload breakglassRotationEvent, previousHandle string, previousDER []byte, nextSigner *signing.RemoteSigner) error {
	if payload.PreviousSignerHandle != previousHandle || !bytes.Equal(payload.PreviousCertificateDER, previousDER) {
		return errors.New("rotation predecessor does not match active replay state")
	}
	if payload.ActiveSignerHandle == "" || payload.ActiveSignerHandle == previousHandle || payload.CeremonyID == "" || payload.RequestDigest == "" {
		return errors.New("rotation event is missing successor, ceremony, or request binding")
	}
	expectedPurpose := breakglass.RotationPurpose(r.tenantID, previousHandle, previousDER, payload.Reason, time.Duration(payload.TTLSeconds)*time.Second)
	if payload.RequestDigest != strings.TrimPrefix(expectedPurpose, "breakglass-rotate:") {
		return errors.New("rotation event request digest does not bind its predecessor, reason, and lifetime")
	}
	if err := (breakglass.Quorum{Threshold: r.threshold, Operators: r.operators}).Verify(payload.Approvers); err != nil {
		return fmt.Errorf("rotation event approvers: %w", err)
	}
	if err := crypto.VerifyCertificateSigner(payload.ActiveCertificateDER, nextSigner.Public()); err != nil {
		return err
	}
	if err := crypto.VerifyCrossSignedCA(payload.PreviousCertificateDER, payload.ActiveCertificateDER, payload.NewSignedByPreviousDER); err != nil {
		return fmt.Errorf("new-by-previous cross-certificate: %w", err)
	}
	if err := crypto.VerifyCrossSignedCA(payload.ActiveCertificateDER, payload.PreviousCertificateDER, payload.PreviousSignedByNewDER); err != nil {
		return fmt.Errorf("previous-by-new cross-certificate: %w", err)
	}
	return nil
}

func (r *configuredBreakglassRuntime) createOrBindRotationSigner(ctx context.Context, handle string) (*signing.RemoteSigner, bool, error) {
	client := r.provider.Client()
	signer, err := client.GenerateDualControlKeyHandle(ctx, crypto.ECDSAP256, handle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, r.signAuthz)
	if err == nil {
		return signer, true, nil
	}
	if status.Code(err) != codes.AlreadyExists {
		return nil, false, err
	}
	signer, err = client.SignerForDualControlHandle(ctx, handle, signing.PurposeCASign, r.signAuthz)
	return signer, false, err
}

func (r *configuredBreakglassRuntime) requireTenant(tenantID string) error {
	if tenantID == "" || tenantID != r.tenantID {
		return errors.New("breakglass: request tenant is not the configured online break-glass tenant")
	}
	return nil
}

func breakglassCeremonyResponse(c store.KeyCeremony) api.BreakglassCeremony {
	return api.BreakglassCeremony{ID: c.ID, TenantID: c.TenantID, Purpose: c.Purpose, Threshold: c.Threshold, Status: c.Status, Approvals: c.Approvals, Opener: c.Opener, CreatedAt: c.CreatedAt}
}

func rotationAPIResponse(value breakglassRotationEvent) api.BreakglassRotation {
	return api.BreakglassRotation{
		PreviousSignerHandle: value.PreviousSignerHandle, ActiveSignerHandle: value.ActiveSignerHandle,
		PreviousCertificatePEM: certificatePEM(value.PreviousCertificateDER), ActiveCertificatePEM: certificatePEM(value.ActiveCertificateDER),
		NewSignedByPreviousPEM: certificatePEM(value.NewSignedByPreviousDER), PreviousSignedByNewPEM: certificatePEM(value.PreviousSignedByNewDER),
		CeremonyID: value.CeremonyID, RequestDigest: value.RequestDigest,
	}
}

func certificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func oneCertificateDER(value string) ([]byte, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("breakglass: certificate_pem must contain exactly one certificate")
	}
	return append([]byte(nil), block.Bytes...), nil
}

func compactSortedOperators(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
