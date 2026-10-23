// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey"
	"trstctl.com/trstctl/internal/keyposture"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const (
	weakKeyAuditInterval      = 6 * time.Hour
	weakKeyAuditFirstDelay    = 15 * time.Minute
	weakKeyAuditTenantTimeout = 15 * time.Minute
	weakKeyAuditPageSize      = 500
	// weakKeyAuditRisk is a factorable key's risk: anyone holding the two
	// public keys can compute both private keys.
	weakKeyAuditRisk = 95
)

// RunWeakKeyAudit runs batch GCD over each tenant's RSA public keys every six
// hours (eMudhra, Part 4): two keys that share a prime can both be factored by
// anyone holding the two public keys, which are public. It runs on the leader
// only, one tenant at a time, never in a request path, and each run is bounded
// to weakkey.MaxSharedFactorModuli distinct keys. The first sweep waits so a
// restart does not add the work to startup.
func (s *Server) RunWeakKeyAudit(ctx context.Context) {
	timer := time.NewTimer(weakKeyAuditFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := s.RunWeakKeyAuditOnce(ctx); err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Error("weak-key audit sweep failed", slog.String("error", err.Error()))
		}
		timer.Reset(weakKeyAuditInterval)
	}
}

// RunWeakKeyAuditOnce audits every tenant once, each within its own bound.
func (s *Server) RunWeakKeyAuditOnce(ctx context.Context) error {
	if s == nil || s.store == nil || s.orch == nil {
		return errors.New("server: weak-key audit is not assembled")
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, tenant := range tenants {
		tenantCtx, cancel := context.WithTimeout(ctx, weakKeyAuditTenantTimeout)
		_, err := s.AuditTenantSharedFactors(tenantCtx, tenant.TenantID)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenant.TenantID, err))
		}
	}
	return errors.Join(errs...)
}

// weakKeyAuditRef is one place a key appears in the inventory.
type weakKeyAuditRef struct {
	ref, fingerprint, subject string
}

// weakKeyAuditKey is one distinct RSA public key and every place it appears.
type weakKeyAuditKey struct {
	spki []byte
	refs []weakKeyAuditRef
}

// AuditTenantSharedFactors collects the tenant's distinct RSA public keys —
// its CA authorities, the inventory certificates whose bytes trstctl holds,
// and the keys discovery readers reported (agents, cloud and CT) — runs batch
// GCD over them and records, as one audit run, a weak-key finding at every
// place a key that shares a prime appears. A tenant with fewer than two RSA
// keys records nothing.
func (s *Server) AuditTenantSharedFactors(ctx context.Context, tenantID string) (weakkey.SharedFactorReport, error) {
	keys, leftOut, err := s.collectTenantRSAKeys(ctx, tenantID)
	if err != nil {
		return weakkey.SharedFactorReport{}, err
	}
	if len(keys) < 2 {
		return weakkey.SharedFactorReport{Keys: len(keys), RSA: len(keys), Distinct: len(keys)}, nil
	}
	ders := make([][]byte, len(keys))
	for i, k := range keys {
		ders[i] = k.spki
	}
	rep, err := weakkey.SharedFactors(ctx, ders)
	if err != nil {
		return rep, err
	}
	var findings []store.DiscoveryFinding
	for _, shared := range rep.Shared {
		reason := weakkey.SharedFactorFinding(len(shared.Partners)).Reason
		for _, place := range keys[shared.Index].refs {
			meta := map[string]any{
				"subject": place.subject, "audit": "batch_gcd",
				"weak_key_check": weakkey.CheckRSASharedFactor, "shared_factor_partners": len(shared.Partners),
				"spki_sha256": crypto.SHA256Hex(keys[shared.Index].spki),
			}
			keyposture.Verdict{WeakReasons: []string{reason}}.AddTo(meta)
			raw, err := json.Marshal(meta)
			if err != nil {
				return rep, err
			}
			findings = append(findings, store.DiscoveryFinding{
				Kind: orchestrator.WeakKeyFindingKind, Ref: place.ref, Provenance: "weak-key-audit:batch-gcd",
				Fingerprint: place.fingerprint, RiskScore: weakKeyAuditRisk, Metadata: raw,
			})
		}
	}
	if _, err := s.orch.RecordWeakKeyAudit(ctx, tenantID, rep, leftOut, findings); err != nil {
		return rep, err
	}
	if s.logger != nil {
		s.logger.Info("weak-key audit ran", slog.String("tenant", tenantID), slog.Int("distinct_rsa_keys", rep.Distinct),
			slog.Int("shared_factor_keys", len(rep.Shared)), slog.Int("left_out", leftOut))
	}
	return rep, nil
}

// collectTenantRSAKeys gathers distinct RSA public keys in a fixed order — CA
// authorities, then inventory certificates, then reported keys — up to the
// batch-GCD bound, and counts the distinct keys it had to leave out.
func (s *Server) collectTenantRSAKeys(ctx context.Context, tenantID string) ([]weakKeyAuditKey, int, error) {
	var keys []weakKeyAuditKey
	bySPKI := map[string]int{}
	leftOut := 0
	add := func(spki []byte, place weakKeyAuditRef) {
		h := crypto.SHA256Hex(spki)
		if i, ok := bySPKI[h]; ok {
			keys[i].refs = append(keys[i].refs, place)
			return
		}
		if len(keys) >= weakkey.MaxSharedFactorModuli {
			leftOut++
			return
		}
		bySPKI[h] = len(keys)
		keys = append(keys, weakKeyAuditKey{spki: spki, refs: []weakKeyAuditRef{place}})
	}
	cas, err := s.store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	for _, ca := range cas {
		der := firstCertificateDER([]byte(ca.CertificatePEM))
		if spki, ok := weakkey.RSASubjectPublicKeyInfo(der); ok {
			add(spki, weakKeyAuditRef{ref: "ca:" + ca.ID, fingerprint: crypto.SHA256Hex(der), subject: ca.CommonName})
		}
	}
	for after := store.ZeroUUID; ; {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		page, err := s.store.ListCertificatesPage(ctx, tenantID, after, nil, weakKeyAuditPageSize, nil)
		if err != nil {
			return nil, 0, err
		}
		for _, cert := range page {
			raw := cert.CertificatePEM
			if len(raw) == 0 {
				raw = cert.CertificateDER
			}
			if spki, ok := weakkey.RSASubjectPublicKeyInfo(firstCertificateDER(raw)); ok {
				add(spki, weakKeyAuditRef{ref: "certificate:" + cert.ID, fingerprint: cert.Fingerprint, subject: cert.Subject})
			}
		}
		if len(page) < weakKeyAuditPageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	for after := store.ZeroUUID; ; {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		page, err := s.store.ListDiscoveryFindingsPage(ctx, tenantID, "", after, weakKeyAuditPageSize)
		if err != nil {
			return nil, 0, err
		}
		for _, f := range page {
			if f.Kind == orchestrator.WeakKeyFindingKind || len(f.Metadata) == 0 {
				continue
			}
			meta := map[string]any{}
			if json.Unmarshal(f.Metadata, &meta) != nil {
				continue
			}
			value, _ := meta[keyposture.MetaRSASPKI].(string)
			spkiHash, _ := meta["spki_sha256"].(string)
			subject, _ := meta["subject"].(string)
			if spki, ok := keyposture.ReportedRSAKey(value, spkiHash); ok {
				add(spki, weakKeyAuditRef{ref: "finding:" + f.ID, fingerprint: f.Fingerprint, subject: subject})
			}
		}
		if len(page) < weakKeyAuditPageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	return keys, leftOut, nil
}

// firstCertificateDER returns the first CERTIFICATE block of a PEM bundle, or
// the input itself when it holds no PEM.
func firstCertificateDER(raw []byte) []byte {
	rest := bytes.TrimSpace(raw)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return raw
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
		rest = remaining
	}
}
