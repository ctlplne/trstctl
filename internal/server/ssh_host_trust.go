// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/store"
)

// sshTrustCertificate is one host certificate as the agent reports it in the
// ssh_trust finding's host_certificates metadata (cmd/trstctl-agent).
type sshTrustCertificate struct {
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

// SSHHostTrust judges every host's newest reported sshd posture against this
// tenant's SSH CA and served KRL (A115). A tenant with no SSH CA here still
// sees each posture; nothing is then judged as trusting the tenant.
func (s *Server) SSHHostTrust(ctx context.Context, tenantID string) (api.SSHHostTrustView, error) {
	view := api.SSHHostTrustView{Hosts: []api.SSHHostTrust{}}
	if s.store == nil {
		return view, nil
	}
	if sp, err := s.sshWorkflowProtocol(tenantID); err == nil {
		if key, err := sp.AuthorityKey(); err == nil {
			if info, err := sshkeys.ParsePublicKey(key); err == nil {
				view.Summary.TenantCAConfigured, view.Summary.TenantCAFingerprint = true, info.FingerprintSHA256
			}
		}
		if err := sp.syncRevocations(ctx, false); err == nil {
			view.Summary.ServedKRLSHA256 = crypto.SHA256Hex(sp.KRLBytes())
		}
	}
	rows, err := s.store.ListSSHTrustPostures(ctx, tenantID, 0)
	if err != nil {
		return api.SSHHostTrustView{}, err
	}
	now := time.Now().UTC()
	for _, row := range rows {
		if err := s.bindAgentlessSSHPosture(ctx, tenantID, &row); err != nil {
			return api.SSHHostTrustView{}, err
		}
		host, err := judgeSSHHostTrust(row, view.Summary.TenantCAFingerprint, view.Summary.ServedKRLSHA256, now)
		if err != nil {
			return api.SSHHostTrustView{}, err
		}
		view.Hosts = append(view.Hosts, host)
		countSSHHostTrust(&view.Summary, host)
	}
	view.Summary.Hosts = len(view.Hosts)
	return view, nil
}

func judgeSSHHostTrust(row store.SSHTrustPosture, tenantCA, servedSHA string, now time.Time) (api.SSHHostTrust, error) {
	var meta map[string]string
	if err := json.Unmarshal(row.Metadata, &meta); err != nil {
		return api.SSHHostTrust{}, fmt.Errorf("decode the sshd trust posture of %s: %w", row.AgentName, err)
	}
	host := api.SSHHostTrust{
		AgentID: row.AgentID, Agent: row.AgentName, SSHDConfig: row.ConfigPath, ConfigRead: meta["config_state"],
		TrustedCAFingerprints: splitNonEmpty(meta["trusted_ca_fingerprints"], ","),
		AuthorizedKeysFile:    splitNonEmpty(meta["authorized_keys_file"], " "),
		HostCertificates:      []api.SSHHostCertificate{},
		FirstObserved:         row.FirstSeenAt.UTC(), LastObserved: row.LastSeenAt.UTC(),
	}
	if meta["collection_mode"] == "agentless" {
		host.CollectionMode, host.TargetAddress, host.SourceID, host.Coverage = meta["collection_mode"], meta["target_address"], meta["source_id"], meta["coverage"]
		host.SSHDConfig = meta["sshd_config"]
	}
	host.MatchBlocks, _ = strconv.Atoi(meta["match_blocks"])
	if host.ConfigRead != "read" {
		host.UserCA, host.HostCertificate, host.RevocationList, host.StandingKeys = host.ConfigRead, host.ConfigRead, host.ConfigRead, host.ConfigRead
		return host, nil
	}

	host.UserCA = judgeUserCA(meta["trusted_ca_state"], host.TrustedCAFingerprints, tenantCA)

	var certificates []sshTrustCertificate
	if raw := meta["host_certificates"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &certificates); err != nil {
			return api.SSHHostTrust{}, fmt.Errorf("decode the host certificates of %s: %w", row.AgentName, err)
		}
	}
	host.HostCertificate = "none"
	for _, c := range certificates {
		judged := api.SSHHostCertificate{
			Path: c.Path, Judgment: judgeHostCertificate(c, tenantCA, now), CAFingerprint: c.CAFingerprint,
			SignatureVerified: c.SignatureVerified, KeyFingerprint: c.KeyFingerprint, KeyID: c.KeyID, Serial: c.Serial,
			Principals: append([]string{}, c.Principals...), ValidAfter: c.ValidAfter, ValidBefore: c.ValidBefore,
		}
		host.HostCertificates = append(host.HostCertificates, judged)
		if hostCertificateRank(judged.Judgment) > hostCertificateRank(host.HostCertificate) {
			host.HostCertificate = judged.Judgment
		}
	}

	switch state := meta["revocation_state"]; state {
	case "krl":
		if version, err := strconv.ParseUint(meta["krl_version"], 10, 64); err == nil {
			host.KRLVersion = &version
		}
		host.RevokedKeysSHA256 = meta["revoked_keys_sha256"]
		host.RevocationList = "not_served"
		if servedSHA != "" && strings.EqualFold(host.RevokedKeysSHA256, servedSHA) {
			host.RevocationList = "served"
		}
	case "key_list":
		host.RevocationList, host.RevokedKeysSHA256 = state, meta["revoked_keys_sha256"]
	case "":
		host.RevocationList = "none"
	default:
		host.RevocationList = state
	}

	host.StandingKeys = "on"
	if len(host.AuthorizedKeysFile) == 1 && strings.EqualFold(host.AuthorizedKeysFile[0], "none") {
		host.StandingKeys = "off"
	}
	return host, nil
}

func judgeUserCA(state string, fingerprints []string, tenantCA string) string {
	switch state {
	case "read":
	case "", "none":
		return "none"
	default:
		return state
	}
	if len(fingerprints) == 0 {
		return "none"
	}
	tenant, other := false, false
	for _, fingerprint := range fingerprints {
		if tenantCA != "" && fingerprint == tenantCA {
			tenant = true
		} else {
			other = true
		}
	}
	switch {
	case tenant && other:
		return "tenant_ca_and_other"
	case tenant:
		return "tenant_ca"
	default:
		return "other_ca"
	}
}

// judgeHostCertificate places one presented certificate against the tenant CA.
// "expiring" means under a third of its validity is left, the point at which a
// renewal should already have run.
func judgeHostCertificate(c sshTrustCertificate, tenantCA string, now time.Time) string {
	if c.State != "certificate" {
		return c.State
	}
	if c.Kind != "host" {
		return "not_host"
	}
	if !c.SignatureVerified {
		return "unverified"
	}
	if tenantCA == "" || c.CAFingerprint != tenantCA {
		return "other_ca"
	}
	after, err := time.Parse(time.RFC3339, c.ValidAfter)
	if err == nil && now.Before(after) {
		return "not_yet_valid"
	}
	if c.ValidBefore == "forever" {
		return "tenant_ca"
	}
	before, err := time.Parse(time.RFC3339, c.ValidBefore)
	if err != nil {
		return "tenant_ca"
	}
	if !now.Before(before) {
		return "expired"
	}
	if !after.IsZero() && before.Sub(now) < before.Sub(after)/3 {
		return "expiring"
	}
	return "tenant_ca"
}

// hostCertificateRank orders judgments so a host is shown with its best
// certificate: a valid tenant certificate outranks everything else.
func hostCertificateRank(judgment string) int {
	switch judgment {
	case "tenant_ca":
		return 6
	case "expiring":
		return 5
	case "not_yet_valid":
		return 4
	case "expired":
		return 3
	case "other_ca":
		return 2
	case "none":
		return 0
	default: // unverified, not_host, invalid, missing, unreadable, relative_path
		return 1
	}
}

func countSSHHostTrust(summary *api.SSHHostTrustSummary, host api.SSHHostTrust) {
	switch host.UserCA {
	case "tenant_ca", "tenant_ca_and_other":
		summary.TrustsTenantCA++
	case "other_ca":
		summary.TrustsOtherCAOnly++
	case "none":
		summary.NoUserCA++
	}
	if host.HostCertificate == "tenant_ca" || host.HostCertificate == "expiring" {
		summary.TenantHostCert++
	}
	if host.RevocationList == "served" {
		summary.EnforcesServedKRL++
	}
	if host.StandingKeys == "on" {
		summary.StandingKeysOn++
	}
}

func splitNonEmpty(value, separator string) []string {
	out := []string{}
	for _, part := range strings.Split(value, separator) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
