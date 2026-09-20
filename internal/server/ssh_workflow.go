// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/events"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

const (
	eventSSHTrustRolloutRecorded = "ssh.trust_rollout.recorded"
	eventSSHCertRevoked          = "ssh.cert.revoked"
	eventSSHHostRetired          = "ssh.host.retired"
	defaultSSHCertificateTTL     = time.Hour
	maxSSHCertificateTTL         = 24 * time.Hour
	defaultAttestedSSHUserTTL    = 15 * time.Minute
	maxAttestedSSHUserTTL        = time.Hour
)

func (s *Server) SSHStatus(ctx context.Context, tenantID string) (api.SSHStatus, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHStatus{}, err
	}
	key, err := sp.AuthorityKey()
	if err != nil {
		return api.SSHStatus{}, fmt.Errorf("%w: authority key unavailable: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	attestors, err := s.sshWorkflowAttestorMethods(ctx, tenantID)
	if err != nil {
		return api.SSHStatus{}, fmt.Errorf("%w: list attester trust sources: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	return api.SSHStatus{
		Served:       true,
		TenantID:     tenantID,
		AuthorityKey: string(key),
		KRLVersion:   sp.KRLVersion(),
		RevokedCount: sp.RevokedCount(),
		Attestors:    attestors,
	}, nil
}

func (s *Server) RecordSSHTrustRollout(ctx context.Context, tenantID, idempotencyKey string, req api.SSHTrustRolloutRequest) (api.SSHTrustRollout, error) {
	if _, err := s.sshWorkflowProtocol(tenantID); err != nil {
		return api.SSHTrustRollout{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "planned"
	}
	if !validSSHTrustRolloutStatus(status) {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: invalid rollout status %q", api.ErrSSHWorkflowInvalid, status)
	}
	hosts := compactStrings(req.TargetHosts)
	if len(hosts) == 0 {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: target_hosts is required", api.ErrSSHWorkflowInvalid)
	}
	requiredEvidence := []struct {
		name  string
		value string
	}{
		{name: "candidate_ca_fingerprint", value: req.CandidateCAFingerprint},
		{name: "reload_command", value: req.ReloadCommand},
		{name: "health_command", value: req.HealthCommand},
		{name: "rollback_plan", value: req.RollbackPlan},
	}
	for _, field := range requiredEvidence {
		if strings.TrimSpace(field.value) == "" {
			return api.SSHTrustRollout{}, fmt.Errorf("%w: %s is required", api.ErrSSHWorkflowInvalid, field.name)
		}
	}
	if !req.Confirmed {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: confirmed must be true for SSH trust rollout evidence", api.ErrSSHWorkflowRejected)
	}
	now := time.Now().UTC()
	out := api.SSHTrustRollout{
		TenantID: tenantID, SourceID: strings.TrimSpace(req.SourceID), TargetHosts: hosts,
		CandidateCAFingerprint: strings.TrimSpace(req.CandidateCAFingerprint),
		ReloadCommand:          strings.TrimSpace(req.ReloadCommand),
		HealthCommand:          strings.TrimSpace(req.HealthCommand),
		RollbackPlan:           strings.TrimSpace(req.RollbackPlan),
		Status:                 status, Confirmed: req.Confirmed, RecordedAt: now,
	}
	data, _ := json.Marshal(out)
	ev, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHTrustRolloutRecorded, data)
	if err != nil {
		return api.SSHTrustRollout{}, err
	}
	out.ID = ev.ID
	return out, nil
}

type normalizedSSHCertificate struct {
	certificateType      string
	publicKey            []byte
	keyID                string
	principals           []string
	requestedTTLSeconds  int64
	effectiveTTL         time.Duration
	ttlDefaulted         bool
	ttlClamped           bool
	publicKeyType        string
	publicKeyFingerprint string
	authorityFingerprint string
	criticalOptions      map[string]string
	extensions           map[string]string
}

func (s *Server) PreviewSSHCertificate(ctx context.Context, tenantID string, req api.SSHCertificateRequest) (api.SSHCertificatePreview, error) {
	_ = ctx // Normalization is intentionally local and effect-free.
	plan, _, err := s.normalizeSSHCertificate(tenantID, req)
	if err != nil {
		return api.SSHCertificatePreview{}, err
	}
	return api.SSHCertificatePreview{
		Capability:              "F43",
		Ready:                   true,
		EffectFree:              true,
		CertificateType:         plan.certificateType,
		KeyID:                   plan.keyID,
		Principals:              append([]string(nil), plan.principals...),
		RequestedTTLSeconds:     plan.requestedTTLSeconds,
		EffectiveTTLSeconds:     int64(plan.effectiveTTL / time.Second),
		TTLDefaulted:            plan.ttlDefaulted,
		TTLClamped:              plan.ttlClamped,
		PublicKeyType:           plan.publicKeyType,
		PublicKeyFingerprint:    plan.publicKeyFingerprint,
		AuthorityFingerprint:    plan.authorityFingerprint,
		CriticalOptions:         cloneSSHStringMap(plan.criticalOptions),
		Extensions:              cloneSSHStringMap(plan.extensions),
		PreviewWrites:           []string{},
		PreviewExternalEffects:  []string{},
		PreviewSignerCalls:      []string{},
		IssuanceWrites:          []string{"append one tenant-scoped ssh.cert.issued audit event"},
		IssuanceExternalEffects: []string{},
		IssuanceSignerCalls:     []string{"sign one SSH " + plan.certificateType + " certificate in the isolated signer"},
		Blockers:                []string{},
		RecoverySteps: []string{
			"Revoke the certificate by serial or key ID.",
			"Distribute the new /ssh/krl artifact to hosts that trust this authority.",
			"Remove the authority from host trust only through a confirmed rollout with a tested rollback path.",
		},
		SecretDataHandling: []string{
			"Only the public SSH key is accepted; trstctl never receives the matching private key.",
			"The certificate is public material and is hidden behind a disclosure in the web console.",
		},
	}, nil
}

func (s *Server) IssueSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req api.SSHCertificateRequest) (api.SSHCertificate, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHCertificate{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	plan, sp, err := s.normalizeSSHCertificate(tenantID, req)
	if err != nil {
		return api.SSHCertificate{}, err
	}
	profile := sshca.Profile{
		Name:           "served-ssh-product",
		MaxTTL:         maxSSHCertificateTTL,
		AllowUserCerts: plan.certificateType == "user",
		AllowHostCerts: plan.certificateType == "host",
	}
	issueRequest := sshca.IssueRequest{
		SubjectPublicKey: append([]byte(nil), plan.publicKey...),
		KeyID:            plan.keyID,
		Principals:       append([]string(nil), plan.principals...),
		TTL:              plan.effectiveTTL,
		CriticalOptions:  cloneSSHStringMap(plan.criticalOptions),
		Extensions:       cloneSSHStringMap(plan.extensions),
	}
	var issued sshca.Issued
	if plan.certificateType == "host" {
		issued, err = sp.CA().IssueHostCert(ctx, profile, issueRequest)
	} else {
		issued, err = sp.CA().IssueUserCert(ctx, profile, issueRequest)
	}
	if err != nil {
		return api.SSHCertificate{}, sshWorkflowIssuanceError(err)
	}
	return api.SSHCertificate{
		Certificate:          string(issued.Certificate),
		CertificateType:      plan.certificateType,
		Serial:               issued.Serial,
		KeyID:                issued.KeyID,
		Principals:           append([]string(nil), plan.principals...),
		ValidBefore:          issued.ValidBefore.UTC().Format(time.RFC3339),
		CriticalOptions:      cloneSSHStringMap(plan.criticalOptions),
		Extensions:           cloneSSHStringMap(plan.extensions),
		AuthorityFingerprint: plan.authorityFingerprint,
		KRLVersion:           sp.KRLVersion(),
	}, nil
}

func (s *Server) normalizeSSHCertificate(tenantID string, req api.SSHCertificateRequest) (normalizedSSHCertificate, *sshProtocol, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return normalizedSSHCertificate{}, nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(req.CertificateType))
	if typ != "host" && typ != "user" {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: certificate_type must be host or user", api.ErrSSHWorkflowInvalid)
	}
	publicKey := []byte(strings.TrimSpace(req.PublicKey))
	if len(publicKey) == 0 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: public_key is required", api.ErrSSHWorkflowInvalid)
	}
	if len(publicKey) > 32<<10 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: public_key is too large", api.ErrSSHWorkflowInvalid)
	}
	keyInfo, err := sshkeys.ParsePublicKey(publicKey)
	if err != nil {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: public_key must be one valid OpenSSH public key", api.ErrSSHWorkflowInvalid)
	}
	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" || len(keyID) > 256 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: key_id is required and must be at most 256 characters", api.ErrSSHWorkflowInvalid)
	}
	if !utf8.ValidString(keyID) || strings.IndexFunc(keyID, unicode.IsControl) >= 0 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: key_id must not contain control characters", api.ErrSSHWorkflowInvalid)
	}
	for _, rawPrincipal := range req.Principals {
		principal := strings.TrimSpace(rawPrincipal)
		if principal != "" && (!utf8.ValidString(principal) || strings.IndexFunc(principal, unicode.IsControl) >= 0) {
			return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: principals must not contain control characters", api.ErrSSHWorkflowInvalid)
		}
	}
	principals := stableUniqueSSHStrings(req.Principals)
	if len(principals) == 0 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: at least one principal is required", api.ErrSSHWorkflowInvalid)
	}
	if len(principals) > 64 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: at most 64 principals are allowed", api.ErrSSHWorkflowInvalid)
	}
	for _, principal := range principals {
		if len(principal) > 256 {
			return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: each principal must be at most 256 characters", api.ErrSSHWorkflowInvalid)
		}
	}

	requestedTTL := req.TTLSeconds
	effectiveTTLSeconds := requestedTTL
	ttlDefaulted := requestedTTL <= 0
	if ttlDefaulted {
		effectiveTTLSeconds = int64(defaultSSHCertificateTTL / time.Second)
	}
	ttlClamped := effectiveTTLSeconds > int64(maxSSHCertificateTTL/time.Second)
	if ttlClamped {
		effectiveTTLSeconds = int64(maxSSHCertificateTTL / time.Second)
	}
	effectiveTTL := time.Duration(effectiveTTLSeconds) * time.Second

	critical, err := normalizeSSHOptionMap(typ, "critical option", req.CriticalOptions, map[string]bool{
		"force-command":  true,
		"source-address": true,
	})
	if err != nil {
		return normalizedSSHCertificate{}, nil, err
	}
	if typ == "host" && len(critical) > 0 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: host certificates do not allow critical options", api.ErrSSHWorkflowInvalid)
	}
	if sourceAddress, ok := critical["source-address"]; ok {
		normalized, err := normalizeSSHSourceAddresses(sourceAddress)
		if err != nil {
			return normalizedSSHCertificate{}, nil, err
		}
		critical["source-address"] = normalized
	}
	if forceCommand, ok := critical["force-command"]; ok && forceCommand == "" {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: force-command cannot be empty", api.ErrSSHWorkflowInvalid)
	}
	defaultExtensions := map[string]string{}
	if typ == "user" {
		defaultExtensions = map[string]string{
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}
	}
	extensions, err := normalizeSSHOptionMap(typ, "extension", req.Extensions, map[string]bool{
		"permit-agent-forwarding": true,
		"permit-port-forwarding":  true,
		"permit-pty":              true,
		"permit-user-rc":          true,
		"permit-X11-forwarding":   true,
	})
	if err != nil {
		return normalizedSSHCertificate{}, nil, err
	}
	if typ == "host" && len(extensions) > 0 {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: host certificates do not allow extensions", api.ErrSSHWorkflowInvalid)
	}
	for key, value := range extensions {
		if value != "" {
			return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: SSH extension %q must have an empty value", api.ErrSSHWorkflowInvalid, key)
		}
		defaultExtensions[key] = value
	}

	authorityKey, err := sp.AuthorityKey()
	if err != nil {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: authority key unavailable: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	authorityInfo, err := sshkeys.ParsePublicKey(authorityKey)
	if err != nil {
		return normalizedSSHCertificate{}, nil, fmt.Errorf("%w: authority key is invalid", api.ErrSSHWorkflowUnavailable)
	}
	return normalizedSSHCertificate{
		certificateType: typ, publicKey: publicKey, keyID: keyID, principals: principals,
		requestedTTLSeconds: requestedTTL, effectiveTTL: effectiveTTL, ttlDefaulted: ttlDefaulted, ttlClamped: ttlClamped,
		publicKeyType: keyInfo.Type, publicKeyFingerprint: keyInfo.FingerprintSHA256,
		authorityFingerprint: authorityInfo.FingerprintSHA256,
		criticalOptions:      critical, extensions: defaultExtensions,
	}, sp, nil
}

func normalizeSSHOptionMap(certificateType, kind string, input map[string]string, allowed map[string]bool) (map[string]string, error) {
	if len(input) > 16 {
		return nil, fmt.Errorf("%w: at most 16 SSH %ss are allowed", api.ErrSSHWorkflowInvalid, kind)
	}
	out := make(map[string]string, len(input))
	for rawKey, rawValue := range input {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if !allowed[key] {
			return nil, fmt.Errorf("%w: %s %q is not allowed for %s certificates", api.ErrSSHWorkflowInvalid, kind, key, certificateType)
		}
		if len(value) > 1024 {
			return nil, fmt.Errorf("%w: %s %q value is too large", api.ErrSSHWorkflowInvalid, kind, key)
		}
		out[key] = value
	}
	return out, nil
}

func stableUniqueSSHStrings(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, value := range input {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeSSHSourceAddresses(input string) (string, error) {
	rawValues := stableUniqueSSHStrings(strings.Split(input, ","))
	if len(rawValues) == 0 {
		return "", fmt.Errorf("%w: source-address must contain at least one IP address or CIDR", api.ErrSSHWorkflowInvalid)
	}
	values := make([]string, 0, len(rawValues))
	seen := make(map[string]struct{}, len(rawValues))
	for _, value := range rawValues {
		normalized := ""
		if prefix, err := netip.ParsePrefix(value); err == nil {
			normalized = prefix.Masked().String()
		} else if address, err := netip.ParseAddr(value); err == nil {
			normalized = address.String()
		} else {
			return "", fmt.Errorf("%w: source-address %q must be an IP address or CIDR", api.ErrSSHWorkflowInvalid, value)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		values = append(values, normalized)
	}
	sort.Strings(values)
	return strings.Join(values, ","), nil
}

func cloneSSHStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

type normalizedAttestedSSHUserCert struct {
	sp                   *sshProtocol
	attestors            []attest.Attestor
	method               string
	supportedMethods     []string
	publicKey            []byte
	publicKeyType        string
	publicKeyFingerprint string
	authorityFingerprint string
	keyID                string
	approver             string
	principals           []string
	sourceAddresses      []string
	forceCommand         string
	criticalOptions      map[string]string
	requestedTTLSeconds  int64
	effectiveTTL         time.Duration
	ttlDefaulted         bool
	ttlClamped           bool
	blockers             []string
}

func (s *Server) PreviewAttestedSSHUserCert(ctx context.Context, tenantID string, req api.SSHAttestedUserCertRequest) (api.SSHAttestedUserCertPreview, error) {
	plan, err := s.normalizeAttestedSSHUserCert(ctx, tenantID, req)
	if err != nil {
		return api.SSHAttestedUserCertPreview{}, err
	}
	return api.SSHAttestedUserCertPreview{
		Capability: "F45", Ready: len(plan.blockers) == 0, EffectFree: true,
		Method: plan.method, SupportedMethods: append([]string(nil), plan.supportedMethods...),
		KeyID: plan.keyID, Approver: plan.approver, Principals: append([]string(nil), plan.principals...),
		SourceAddresses: append([]string(nil), plan.sourceAddresses...), ForceCommand: plan.forceCommand,
		RequestedTTLSeconds: plan.requestedTTLSeconds, EffectiveTTLSeconds: int64(plan.effectiveTTL / time.Second),
		TTLDefaulted: plan.ttlDefaulted, TTLClamped: plan.ttlClamped,
		PublicKeyType: plan.publicKeyType, PublicKeyFingerprint: plan.publicKeyFingerprint,
		AuthorityFingerprint: plan.authorityFingerprint, RequiredPermission: "certs:issue",
		AttestationVerification: "execution_only", PayloadSHA256: crypto.SHA256Hex(req.Payload),
		PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		ExecutionWrites: []string{
			"Record tenant-scoped attestation verification and SSH certificate issuance audit evidence.",
			"Record the idempotent HTTP result so an unchanged retry returns the original certificate.",
		},
		ExecutionExternalEffects: []string{},
		ExecutionSignerCalls: []string{
			"Ask the isolated signer to sign one short-lived SSH user certificate after proof, approver, principal, and session constraints pass.",
		},
		Blockers: append([]string{}, plan.blockers...),
		RecoverySteps: []string{
			"If the response is lost or the server returns a temporary error, retry the exact request with the same Idempotency-Key. trstctl returns the original result instead of signing twice.",
			"If proof verification fails, obtain fresh proof or repair the tenant trust source, then build a new preview. Never disable verification to continue.",
			"If the signer is unavailable, restore the isolated signer and retry the unchanged request with the same Idempotency-Key.",
			"If access must be removed after issuance, revoke the certificate by serial or key ID and distribute the updated /ssh/krl artifact.",
		},
		DataHandling: []string{
			"The preview returns a SHA-256 proof digest, never the raw proof. Decoded proof buffers are wiped after the response.",
			"Proof verification happens only during issuance so preview cannot consume one-time evidence or create verification audit events.",
			"Only the public SSH key enters trstctl; the matching private key remains with the requester.",
		},
	}, nil
}

func (s *Server) normalizeAttestedSSHUserCert(ctx context.Context, tenantID string, req api.SSHAttestedUserCertRequest) (normalizedAttestedSSHUserCert, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return normalizedAttestedSSHUserCert{}, err
	}
	plan := normalizedAttestedSSHUserCert{sp: sp, criticalOptions: map[string]string{}, requestedTTLSeconds: req.TTLSeconds}
	if s.attestedIssuance == nil {
		return normalizedAttestedSSHUserCert{}, fmt.Errorf("%w: attestors are not configured", api.ErrSSHWorkflowUnavailable)
	}
	plan.supportedMethods, err = s.sshWorkflowAttestorMethods(ctx, tenantID)
	if err != nil {
		return normalizedAttestedSSHUserCert{}, fmt.Errorf("%w: list attester trust sources: %v", api.ErrSSHWorkflowUnavailable, err)
	}

	method := strings.TrimSpace(req.Method)
	plan.method = method
	if method == "" {
		plan.blockers = append(plan.blockers, "Choose an attestation method configured for this tenant.")
	} else {
		plan.attestors, err = s.attestedIssuance.attestorsForMethod(ctx, tenantID, method)
		if err != nil {
			return normalizedAttestedSSHUserCert{}, fmt.Errorf("%w: list attester trust sources: %v", api.ErrSSHWorkflowUnavailable, err)
		}
		if len(plan.attestors) == 0 {
			plan.blockers = append(plan.blockers, fmt.Sprintf("Attestation method %q is not configured for this tenant.", method))
		}
	}
	if len(req.Payload) == 0 {
		plan.blockers = append(plan.blockers, "Provide the attestation proof before issuing.")
	}

	plan.publicKey = []byte(strings.TrimSpace(req.PublicKey))
	switch {
	case len(plan.publicKey) == 0:
		plan.blockers = append(plan.blockers, "Provide one valid OpenSSH public key. Keep the matching private key outside trstctl.")
	case len(plan.publicKey) > 32<<10:
		plan.blockers = append(plan.blockers, "The SSH public key is too large.")
	default:
		keyInfo, parseErr := sshkeys.ParsePublicKey(plan.publicKey)
		if parseErr != nil {
			plan.blockers = append(plan.blockers, "Provide one valid OpenSSH public key in authorized_keys form.")
		} else {
			plan.publicKeyType = keyInfo.Type
			plan.publicKeyFingerprint = keyInfo.FingerprintSHA256
		}
	}

	plan.keyID = strings.TrimSpace(req.KeyID)
	if plan.keyID != "" && !validAttestedSSHText(plan.keyID, 256) {
		plan.blockers = append(plan.blockers, "Key ID must be at most 256 characters and contain no control characters.")
	}
	plan.approver = strings.TrimSpace(req.Approver)
	if !validAttestedSSHText(plan.approver, 256) {
		plan.blockers = append(plan.blockers, "Name a distinct approver using at most 256 characters and no control characters.")
	}
	principals, principalErr := normalizeAttestedSSHList(req.Principals, 64, 256)
	if principalErr != nil {
		plan.blockers = append(plan.blockers, "Principals must contain at most 64 unique values; each value must be at most 256 characters with no control characters.")
	} else {
		plan.principals = principals
	}
	if len(req.SourceAddresses) > 0 {
		sourceAddress, sourceErr := normalizeSSHSourceAddresses(strings.Join(req.SourceAddresses, ","))
		if sourceErr != nil {
			plan.blockers = append(plan.blockers, strings.TrimPrefix(sourceErr.Error(), api.ErrSSHWorkflowInvalid.Error()+": "))
		} else {
			plan.sourceAddresses = strings.Split(sourceAddress, ",")
			plan.criticalOptions["source-address"] = sourceAddress
		}
	}
	plan.forceCommand = strings.TrimSpace(req.ForceCommand)
	if plan.forceCommand != "" {
		if !validAttestedSSHText(plan.forceCommand, 1024) {
			plan.blockers = append(plan.blockers, "Force command must be at most 1,024 characters and contain no control characters.")
		} else {
			plan.criticalOptions["force-command"] = plan.forceCommand
		}
	}
	plan.ttlDefaulted = req.TTLSeconds <= 0
	effectiveTTLSeconds := req.TTLSeconds
	if plan.ttlDefaulted {
		effectiveTTLSeconds = int64(defaultAttestedSSHUserTTL / time.Second)
	}
	plan.ttlClamped = effectiveTTLSeconds > int64(maxAttestedSSHUserTTL/time.Second)
	if plan.ttlClamped {
		effectiveTTLSeconds = int64(maxAttestedSSHUserTTL / time.Second)
	}
	plan.effectiveTTL = time.Duration(effectiveTTLSeconds) * time.Second

	authorityKey, err := sp.AuthorityKey()
	if err != nil {
		return normalizedAttestedSSHUserCert{}, fmt.Errorf("%w: authority key unavailable: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	authorityInfo, err := sshkeys.ParsePublicKey(authorityKey)
	if err != nil {
		return normalizedAttestedSSHUserCert{}, fmt.Errorf("%w: authority key is invalid", api.ErrSSHWorkflowUnavailable)
	}
	plan.authorityFingerprint = authorityInfo.FingerprintSHA256
	return plan, nil
}

func (s *Server) IssueAttestedSSHUserCert(ctx context.Context, tenantID, idempotencyKey string, req api.SSHAttestedUserCertRequest) (api.SSHAttestedUserCert, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	plan, err := s.normalizeAttestedSSHUserCert(ctx, tenantID, req)
	if err != nil {
		return api.SSHAttestedUserCert{}, err
	}
	if len(plan.blockers) > 0 {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: %s", api.ErrSSHWorkflowInvalid, plan.blockers[0])
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: plan.attestors,
		Audit:     attestedIssuanceAuditor(s.eventLogForSSHWorkflow()),
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrSSHWorkflowInvalid, err)
	}
	issuer, err := sshca.NewAttestedUserCertIssuer(sshca.AttestedConfig{
		TenantID: tenantID,
		CA:       plan.sp.CA(),
		Verifier: verifier,
		Profile: sshca.Profile{
			Name:           "served-ssh-attested",
			MaxTTL:         time.Hour,
			AllowUserCerts: true,
			DefaultExtensions: map[string]string{
				"permit-pty": "",
			},
		},
		TTL:   plan.effectiveTTL,
		Audit: attestedIssuanceAuditor(s.eventLogForSSHWorkflow()),
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	issued, att, err := issuer.Issue(ctx, sshca.AttestedRequest{
		Method:           plan.method,
		Payload:          req.Payload,
		SubjectPublicKey: plan.publicKey,
		KeyID:            plan.keyID,
		Approver:         plan.approver,
		Principals:       plan.principals,
		CriticalOptions:  plan.criticalOptions,
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, sshWorkflowIssuanceError(err)
	}
	responsePrincipals := plan.principals
	if len(responsePrincipals) == 0 {
		responsePrincipals = []string{att.Subject}
	}
	return api.SSHAttestedUserCert{
		Certificate:     string(issued.Certificate),
		Serial:          issued.Serial,
		KeyID:           issued.KeyID,
		Subject:         att.Subject,
		Principals:      responsePrincipals,
		ValidBefore:     issued.ValidBefore.UTC().Format(time.RFC3339),
		Approver:        plan.approver,
		SourceAddresses: plan.sourceAddresses,
		ForceCommand:    plan.forceCommand,
		Attestation:     att,
	}, nil
}

// sshWorkflowIssuanceError keeps a broken signing road separate from a denied
// request. ELI5: if the proof or policy is bad, the operator must change the
// request (403). If the isolated signer is restarting or unreachable, the exact
// same reviewed request is still valid and should be retried after recovery
// (503). Internal socket/provider details do not cross the API boundary.
func sshWorkflowIssuanceError(err error) error {
	if sshWorkflowInfrastructureRetryable(err) {
		return fmt.Errorf("%w: SSH signing service is temporarily unavailable; restore it and retry the exact request with the same Idempotency-Key", api.ErrSSHWorkflowUnavailable)
	}
	return fmt.Errorf("%w: %v", api.ErrSSHWorkflowRejected, err)
}

func sshWorkflowInfrastructureRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Aborted, codes.Internal, codes.Unavailable, codes.DataLoss:
		return true
	default:
		return false
	}
}

func validAttestedSSHText(value string, maxLen int) bool {
	return value != "" && len(value) <= maxLen && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func normalizeAttestedSSHList(values []string, maxItems, maxLen int) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if !validAttestedSSHText(value, maxLen) {
			return nil, api.ErrSSHWorkflowInvalid
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) > maxItems {
		return nil, api.ErrSSHWorkflowInvalid
	}
	sort.Strings(out)
	return out, nil
}

func (s *Server) RevokeSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHStatus{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHStatus{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	if req.Serial == 0 && strings.TrimSpace(req.KeyID) == "" {
		return api.SSHStatus{}, fmt.Errorf("%w: serial or key_id is required", api.ErrSSHWorkflowInvalid)
	}
	data, _ := json.Marshal(req)
	if _, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHCertRevoked, data); err != nil {
		return api.SSHStatus{}, err
	}
	sp.Revoke(req.Serial, strings.TrimSpace(req.KeyID))
	return s.SSHStatus(ctx, tenantID)
}

func (s *Server) RetireSSHHost(ctx context.Context, tenantID, idempotencyKey string, req api.SSHHostRetireRequest) (api.SSHHostRetirement, error) {
	if _, err := s.sshWorkflowProtocol(tenantID); err != nil {
		return api.SSHHostRetirement{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHHostRetirement{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return api.SSHHostRetirement{}, fmt.Errorf("%w: host is required", api.ErrSSHWorkflowInvalid)
	}
	out := api.SSHHostRetirement{
		TenantID: tenantID, Host: host, SourceID: strings.TrimSpace(req.SourceID),
		RunID: strings.TrimSpace(req.RunID), IdentityID: strings.TrimSpace(req.IdentityID),
		Reason: strings.TrimSpace(req.Reason), Status: "retired", RecordedAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(out)
	ev, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHHostRetired, data)
	if err != nil {
		return api.SSHHostRetirement{}, err
	}
	out.ID = ev.ID
	return out, nil
}

func (s *Server) sshWorkflowProtocol(tenantID string) (*sshProtocol, error) {
	if s.protocols == nil || s.protocols.ssh == nil {
		return nil, api.ErrSSHWorkflowUnavailable
	}
	if tenantID == "" || tenantID != s.protocols.ssh.tenantID {
		return nil, fmt.Errorf("%w: tenant is not bound to the served SSH protocol", api.ErrSSHWorkflowRejected)
	}
	return s.protocols.ssh, nil
}

func (s *Server) appendSSHWorkflowEvent(ctx context.Context, tenantID, typ string, data []byte) (events.Event, error) {
	if s == nil || s.log == nil {
		return events.Event{}, fmt.Errorf("%w: event log is unavailable", api.ErrSSHWorkflowUnavailable)
	}
	return s.log.Append(ctx, events.Event{Type: typ, TenantID: tenantID, Data: data})
}

func (s *Server) eventLogForSSHWorkflow() *events.Log {
	if s == nil {
		return nil
	}
	return s.log
}

func (s *Server) sshWorkflowAttestorMethods(ctx context.Context, tenantID string) ([]string, error) {
	if s == nil || s.attestedIssuance == nil {
		return nil, nil
	}
	methods := make(map[string]struct{}, len(s.attestedIssuance.attestors))
	for _, a := range s.attestedIssuance.attestors {
		if a != nil && a.Method() != "" {
			methods[a.Method()] = struct{}{}
		}
	}
	if s.attestedIssuance.store != nil {
		sources, err := s.attestedIssuance.store.ListWorkloadAttesterTrustSources(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			if source.Enabled && strings.TrimSpace(source.Method) != "" {
				methods[source.Method] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out, nil
}

func validSSHTrustRolloutStatus(status string) bool {
	switch status {
	case "planned", "validating", "health_passed", "rolled_back", "failed":
		return true
	default:
		return false
	}
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// SSHFleetInventory answers B-2: which hosts still carry standing SSH key
// access. Every ssh_keys row is a raw key — a CA-minted certificate is not
// stored there — so this view IS the not-under-CA list, and the API layer
// says so explicitly rather than leaving the reader to infer it.
func (s *Server) SSHFleetInventory(ctx context.Context, tenantID string) ([]api.SSHFleetHost, error) {
	if s.store == nil {
		return nil, nil
	}
	hosts, err := s.store.SSHFleetInventory(ctx, tenantID, 0)
	if err != nil {
		return nil, err
	}
	out := make([]api.SSHFleetHost, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, api.SSHFleetHost{
			Location: host.Location, Keys: host.Keys,
			StandingKeys: host.StandingKeys, OrphanedKeys: host.OrphanedKeys,
			KeyTypes: host.KeyTypes, Sources: host.Sources,
			FirstObserved: host.FirstObserved, LastObserved: host.LastObserved,
		})
	}
	return out, nil
}
