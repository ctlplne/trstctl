// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
)

// SSH certificate leases (A239-L11). An ssh-certificate provider issues each
// lease a fresh Ed25519 key pair and a certificate from the control plane's own
// SSH CA, for its role's principals and the lease's lifetime. The key pair is
// prepared, and sealed by the outbox worker, before the CA signs anything, so a
// retry after a lost answer certifies the same key again rather than a new
// one. Every certificate of a lease carries the key ID trstctl-<lease ID>.
// Revoking the lease revokes that key ID on the served KRL, so a host that
// loads the KRL refuses each of them before its expiry. A lease that ends
// after its certificate expired (the usual end of a lease) adds nothing to the
// KRL: the certificate no longer authenticates anywhere, and the KRL keeps
// only early revocations rather than one entry per lease forever.

const (
	sshLeaseKeyIDPrefix = "trstctl-"
	sshLeaseRefPrefix   = "ssh-key-id:"
)

type configuredSSHCertificateProvider struct {
	*configuredDynamicProvider
	issue  func(ctx context.Context, tenantID, idempotencyKey string, req api.SSHCertificateRequest) (api.SSHCertificate, error)
	revoke func(ctx context.Context, tenantID, idempotencyKey string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error)
	// clock is the time Revoke compares a certificate's expiry with; the
	// wall clock when nil.
	clock func() time.Time
}

func (p *configuredSSHCertificateProvider) now() time.Time {
	if p.clock != nil {
		return p.clock()
	}
	return time.Now()
}

// attachSSHCertificateProviders binds every ssh-certificate provider to this
// server's SSH CA. The registry's providers are built from configuration
// before the server exists, so each consumer attaches a copy, as the native
// Windows rotation provider does.
func (s *Server) attachSSHCertificateProviders(providers []dynsecret.Provider) []dynsecret.Provider {
	result := append([]dynsecret.Provider(nil), providers...)
	for i, p := range result {
		if ssh, ok := p.(*configuredSSHCertificateProvider); ok {
			attached := *ssh
			attached.issue = s.IssueSSHCertificate
			attached.revoke = s.RevokeSSHCertificate
			result[i] = &attached
		}
	}
	return result
}

// Generate is refused: a lease's key pair is prepared and sealed first.
func (p *configuredSSHCertificateProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("server: an ssh-certificate lease is issued from its sealed key pair")
}

// Prepare generates the lease's key pair, locally. The outbox worker seals it
// before the first signature.
func (p *configuredSSHCertificateProvider) Prepare(_ context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	if err := p.checkLease(req); err != nil {
		return nil, err
	}
	private, _, err := crypto.GenerateSSHClientKey(sshLeaseKeyIDPrefix + req.LeaseID)
	return private, err
}

// GeneratePrepared certifies the prepared key for the role's principals.
func (p *configuredSSHCertificateProvider) GeneratePrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	if err := p.checkLease(req); err != nil {
		return dynsecret.Credential{}, err
	}
	if p.issue == nil {
		return dynsecret.Credential{}, errors.New("server: the ssh-certificate provider is not attached to the control plane's SSH CA")
	}
	public, err := crypto.SSHAuthorizedKeyOfPrivateKey(prepared)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	role := p.cfg.SSHRoles[req.Role]
	certificateType := strings.TrimSpace(role.CertificateType)
	if certificateType == "" {
		certificateType = "user"
	}
	keyID := sshLeaseKeyIDPrefix + req.LeaseID
	issued, err := p.issue(ctx, p.tenantID, "dynsecret-ssh-"+req.LeaseID, api.SSHCertificateRequest{
		CertificateType: certificateType, PublicKey: string(public), KeyID: keyID,
		Principals: append([]string(nil), role.Principals...), TTLSeconds: int64(req.TTL / time.Second),
		CriticalOptions: cloneSSHStringMap(role.CriticalOptions), Extensions: cloneSSHStringMap(role.Extensions),
	})
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("server: ssh-certificate provider %q: %w", p.id, err)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		PrivateKey           secret.JSONBytes `json:"private_key"`
		Certificate          string           `json:"certificate"`
		CertificateType      string           `json:"certificate_type"`
		KeyID                string           `json:"key_id"`
		Serial               uint64           `json:"serial"`
		Principals           []string         `json:"principals"`
		ValidBefore          string           `json:"valid_before"`
		AuthorityFingerprint string           `json:"authority_fingerprint"`
	}{PrivateKey: prepared, Certificate: issued.Certificate, CertificateType: issued.CertificateType, KeyID: issued.KeyID,
		Serial: issued.Serial, Principals: issued.Principals, ValidBefore: issued.ValidBefore, AuthorityFingerprint: issued.AuthorityFingerprint})
	if err != nil {
		return dynsecret.Credential{}, err
	}
	validBefore, err := time.Parse(time.RFC3339, issued.ValidBefore)
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("server: ssh-certificate provider %q: the certificate's expiry %q", p.id, issued.ValidBefore)
	}
	return dynsecret.Credential{
		BackendRef: sshLeaseRefPrefix + keyID + "@" + strconv.FormatInt(validBefore.Unix(), 10),
		Secret:     credential,
		Metadata: map[string]string{
			"key_id": keyID, "serial": fmt.Sprint(issued.Serial), "principals": strings.Join(issued.Principals, ","),
			"valid_before": issued.ValidBefore, "authority_fingerprint": issued.AuthorityFingerprint,
		},
	}, nil
}

// Revoke revokes the lease's key ID on the served KRL: every certificate the
// lease's key was given, a retry's included. Once the certificates have
// expired there is nothing left to revoke, so the KRL is left as it is.
func (p *configuredSSHCertificateProvider) Revoke(ctx context.Context, backendRef string) error {
	rest, ok := strings.CutPrefix(backendRef, sshLeaseRefPrefix)
	keyID, expiry, hasExpiry := strings.Cut(rest, "@")
	if !ok || !hasExpiry || !strings.HasPrefix(keyID, sshLeaseKeyIDPrefix) || len(keyID) == len(sshLeaseKeyIDPrefix) {
		return fmt.Errorf("server: ssh-certificate provider %q: %q is not an SSH lease reference", p.id, backendRef)
	}
	validBefore, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return fmt.Errorf("server: ssh-certificate provider %q: %q is not an SSH lease reference", p.id, backendRef)
	}
	if !p.now().Before(time.Unix(validBefore, 0)) {
		return nil
	}
	if p.revoke == nil {
		return errors.New("server: the ssh-certificate provider is not attached to the control plane's SSH CA")
	}
	if _, err := p.revoke(ctx, p.tenantID, "dynsecret-ssh-revoke-"+keyID, api.SSHRevokeCertificateRequest{KeyID: keyID, Reason: "dynamic secret lease revoked"}); err != nil {
		return fmt.Errorf("server: ssh-certificate provider %q: %w", p.id, err)
	}
	return nil
}

// RevokeMethod and RevokeCredential revoke as Revoke does: the reference
// alone names every certificate of the lease.
func (p *configuredSSHCertificateProvider) RevokeMethod(ctx context.Context, backendRef string) (string, error) {
	return "", p.Revoke(ctx, backendRef)
}

func (p *configuredSSHCertificateProvider) RevokeCredential(ctx context.Context, backendRef string, _ []byte) error {
	return p.Revoke(ctx, backendRef)
}

// DynamicSecretRevocation is confirmed: the revocation is on the CA's own KRL
// before the lease reads revoked.
func (p *configuredSSHCertificateProvider) DynamicSecretRevocation() string { return "confirmed" }

func (p *configuredSSHCertificateProvider) checkLease(req dynsecret.GenerateRequest) error {
	switch {
	case req.Static:
		return fmt.Errorf("dynamic-secret provider %q issues leases only", p.id)
	case !p.allowedRoles[req.Role]:
		return fmt.Errorf("dynamic-secret provider %q does not allow role %q", p.id, req.Role)
	case len(p.cfg.SSHRoles[req.Role].Principals) == 0:
		return fmt.Errorf("dynamic-secret provider %q role %q names no principals", p.id, req.Role)
	case req.TTL < time.Second || req.TTL > p.maxTTL:
		return fmt.Errorf("dynamic-secret provider %q TTL must be between 1s and %s", p.id, p.maxTTL)
	case strings.TrimSpace(req.LeaseID) == "":
		return fmt.Errorf("dynamic-secret provider %q needs the lease's ID", p.id)
	}
	return nil
}
