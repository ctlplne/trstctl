// SPDX-License-Identifier: BUSL-1.1
package sshdiscovery

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TrustInventoryFinding is a public posture ready for either inventory channel.
// Keeping this type local avoids coupling the host reader to gRPC transport.
type TrustInventoryFinding struct {
	Kind, Ref, Provenance, Fingerprint string
	RiskScore                          int
	Metadata                           map[string]string
}

// TrustCertificateReport is one HostCertificate in an ssh_trust finding.
// The control plane decodes the same shape (internal/server/ssh_host_trust.go).
type TrustCertificateReport struct {
	Path              string   `json:"path"`
	State             string   `json:"state"`
	Kind              string   `json:"kind,omitempty"`
	CAFingerprint     string   `json:"ca_fingerprint,omitempty"`
	SignatureVerified bool     `json:"signature_verified"`
	KeyFingerprint    string   `json:"key_fingerprint,omitempty"`
	KeyID             string   `json:"key_id,omitempty"`
	Serial            uint64   `json:"serial,omitempty"`
	Principals        []string `json:"principals,omitempty"`
	ValidAfter        string   `json:"valid_after,omitempty"`
	ValidBefore       string   `json:"valid_before,omitempty"`
}

// sshTrustInventoryFindings reports each sshd configuration's trust posture as
// one ssh_trust finding (A115): public fingerprints, paths, versions and
// digests only. The finding's fingerprint is the digest of what it reports,
// so a changed configuration is a new finding and the newest is the host's
// current answer.
func InventoryFindings(postures []SSHDTrust) ([]TrustInventoryFinding, error) {
	out := make([]TrustInventoryFinding, 0, len(postures))
	for _, t := range postures {
		certificates := make([]TrustCertificateReport, 0, len(t.HostCertificates))
		for _, c := range t.HostCertificates {
			report := TrustCertificateReport{Path: c.Path, State: c.State}
			if c.State == StateCertificate {
				info := c.Certificate
				report.Kind, report.CAFingerprint, report.SignatureVerified = info.Kind, info.CAFingerprintSHA256, info.SignatureVerified
				report.KeyFingerprint, report.KeyID, report.Serial = info.KeyFingerprintSHA256, info.KeyID, info.Serial
				report.Principals = info.Principals
				report.ValidAfter, report.ValidBefore = info.ValidAfter.UTC().Format(time.RFC3339), c.ValidBeforeText()
			}
			certificates = append(certificates, report)
		}
		encoded, err := json.Marshal(certificates)
		if err != nil {
			return nil, fmt.Errorf("encode host certificates of %s: %w", t.ConfigPath, err)
		}
		cas := make([]string, 0, len(t.TrustedCAs))
		for _, ca := range t.TrustedCAs {
			cas = append(cas, ca.FingerprintSHA256)
		}
		meta := map[string]string{
			"sshd_config": t.ConfigPath, "config_state": t.ConfigState,
			"trusted_user_ca_keys": t.TrustedUserCAKeys, "trusted_ca_state": t.TrustedCAState,
			"trusted_ca_fingerprints": strings.Join(cas, ","),
			"revoked_keys":            t.RevokedKeys, "revocation_state": t.RevocationState,
			"revoked_keys_sha256":  t.RevokedKeysSHA256,
			"host_certificates":    string(encoded),
			"authorized_keys_file": strings.Join(t.AuthorizedKeysFile, " "), "authorized_principals_file": t.AuthorizedPrincipalsFile,
			"match_blocks": strconv.Itoa(t.MatchBlocks), "included_files": strconv.Itoa(t.IncludedFiles),
			"key_bytes": "not_collected",
		}
		if t.RevocationState == StateKRL {
			meta["krl_version"] = strconv.FormatUint(t.KRLVersion, 10)
		}
		canonical, err := json.Marshal(meta) // encoding/json sorts map keys, so equal postures digest equally
		if err != nil {
			return nil, fmt.Errorf("encode sshd trust posture of %s: %w", t.ConfigPath, err)
		}
		out = append(out, TrustInventoryFinding{
			Kind: TrustFindingKind, Ref: t.ConfigPath,
			Provenance:  "ssh:sshd-trust:" + t.ConfigPath,
			Fingerprint: crypto.SHA256Hex(canonical), RiskScore: 20, Metadata: meta,
		})
	}
	return out, nil
}
