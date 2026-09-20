// SPDX-License-Identifier: BUSL-1.1

package compatlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// The signed readiness report (epic M1).
//
// Assess produces a verdict; this is how that verdict LEAVES the lab as
// evidence somebody can act on and later prove was not edited. A readiness
// report is a recommendation about a migration nobody can easily reverse, so
// the artifact it travels as must be signed inside the isolated signer (AN-3)
// and verifiable offline — a report an operator cannot check is a rumour with
// a logo.
//
// The report carries the FULL evidence, not just the verdict: the cohort's
// targeted clients, every per-client outcome WITH its handshake cost, and the
// verdict Assess derived. That is deliberate. A reader must be able to
// re-derive the verdict from the evidence rather than trust the sentence, and
// the cost numbers are half the answer — a cohort that negotiated but tripled
// handshake size is a different recommendation from one that negotiated
// cheaply, and a report that signed only "ready" would be recommending an
// outage.

// ArtifactKindReadinessReport is the artifact kind a PQC readiness report signs
// under. The signer binds it, so a readiness report cannot be minted by a path
// authorized to sign some other artifact.
const ArtifactKindReadinessReport = "pqc-readiness-report"

// ReportSpecVersion pins the canonical layout an offline verifier expects.
const ReportSpecVersion = "pqc.compatlab/v1"

// ArtifactSigningClient is satisfied by *signing.Client and by signer-side test
// doubles. It requests a signature but never holds the key.
type ArtifactSigningClient interface {
	SignArtifact(context.Context, signing.ArtifactSignRequest) (signing.ArtifactSignature, error)
}

// Report is the canonical, signable body of a readiness report.
type Report struct {
	SpecVersion string   `json:"spec_version"`
	TenantID    string   `json:"tenant_id"`
	AuthorityID string   `json:"authority_id"`
	Cohort      string   `json:"cohort"`
	Targeted    []string `json:"targeted"`
	Results     []Result `json:"results"`
	Verdict     Verdict  `json:"verdict"`
	// GeneratedAt is a caller-supplied unix timestamp. The lab has no clock of
	// its own here; the caller stamps it so the report is reproducible.
	GeneratedAt int64 `json:"generated_at"`
}

// BuildReport assembles a report from a cohort, re-running Assess so the signed
// verdict is DERIVED from the evidence in the same artifact rather than passed
// in alongside it — a caller cannot sign "ready" over evidence that says
// otherwise.
func BuildReport(tenantID, authorityID string, c Cohort, generatedAt int64) (Report, error) {
	tenantID = strings.TrimSpace(tenantID)
	authorityID = strings.TrimSpace(authorityID)
	if tenantID == "" || authorityID == "" {
		return Report{}, fmt.Errorf("compatlab: report needs tenant and authority")
	}
	if strings.TrimSpace(c.Name) == "" {
		return Report{}, fmt.Errorf("compatlab: report needs a cohort name")
	}
	if len(c.Targeted) == 0 {
		return Report{}, fmt.Errorf("compatlab: a cohort that targeted no clients is not a report")
	}
	return Report{
		SpecVersion: ReportSpecVersion,
		TenantID:    tenantID,
		AuthorityID: authorityID,
		Cohort:      strings.TrimSpace(c.Name),
		Targeted:    normalizeTargets(c.Targeted),
		Results:     normalizeResults(c.Results),
		Verdict:     Assess(c),
		GeneratedAt: generatedAt,
	}, nil
}

// CanonicalBytes is the deterministic byte form the signature covers. Targets
// and results are sorted so the same evidence signs to the same bytes
// regardless of the order it arrived in.
func (r Report) CanonicalBytes() ([]byte, error) {
	if r.SpecVersion == "" {
		return nil, fmt.Errorf("compatlab: report has no spec version")
	}
	canon := r
	canon.Targeted = normalizeTargets(r.Targeted)
	canon.Results = normalizeResults(r.Results)
	return json.Marshal(canon)
}

// SignedReport is the report plus the signer-side signature material.
type SignedReport struct {
	Report       Report           `json:"report"`
	ReportHash   []byte           `json:"report_hash"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
}

// SignReport signs the report inside the isolated signer. The report bytes are
// hashed and signed by the signer process; the private key never crosses the
// boundary.
func SignReport(ctx context.Context, client ArtifactSigningClient, report Report, keyID string) (SignedReport, error) {
	if client == nil {
		return SignedReport{}, fmt.Errorf("compatlab: no artifact signer")
	}
	body, err := report.CanonicalBytes()
	if err != nil {
		return SignedReport{}, err
	}
	hash := crypto.SHA256Sum(body)
	res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        ArtifactKindReadinessReport,
		TenantID:    report.TenantID,
		AuthorityID: report.AuthorityID,
		KeyID:       strings.TrimSpace(keyID),
		Payload:     body,
	})
	if err != nil {
		return SignedReport{}, err
	}
	return SignedReport{
		Report:       report,
		ReportHash:   hash,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
	}, nil
}

// Verify checks the report body, its hash, the trusted key, and the signature.
// The trusted map is keyed by KeyID: an embedded public key alone is not enough,
// or a report could vouch for itself with a key nobody trusts.
func (s SignedReport) Verify(trusted map[string]crypto.PublicKey) error {
	if s.KeyID == "" || len(s.Signature) == 0 || len(s.PublicKeyDER) == 0 {
		return fmt.Errorf("compatlab: report is not signed")
	}
	body, err := s.Report.CanonicalBytes()
	if err != nil {
		return err
	}
	hash := crypto.SHA256Sum(body)
	if !bytes.Equal(hash, s.ReportHash) {
		return fmt.Errorf("compatlab: report hash does not match its body")
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return fmt.Errorf("compatlab: report signed by an untrusted key %q", s.KeyID)
	}
	if !bytes.Equal(pub.DER, s.PublicKeyDER) {
		return fmt.Errorf("compatlab: report public key does not match the trusted key for %q", s.KeyID)
	}
	if err := crypto.VerifyDigest(pub, hash, s.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("compatlab: report signature verification failed: %w", err)
	}
	return nil
}

func normalizeTargets(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeResults(in []Result) []Result {
	out := make([]Result, 0, len(in))
	for _, r := range in {
		r.ClientID = strings.TrimSpace(r.ClientID)
		if r.ClientID == "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out
}
