// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
)

// A84: a workload's own attestation proof as its credential.
//
// A GitHub Actions workflow used to need two things to get a certificate: its
// ambient OIDC token (the attestation, saying WHICH workflow asked) and a
// trstctl API token scoped to certs:issue (the credential, saying it MAY ask).
// The second is a long-lived secret in every pipeline. When the tenant marks
// a github_oidc trust source self_authenticating, the verified OIDC token is
// both: it is accepted as the bearer credential of the attested-issuance
// routes alone, for the tenant named in X-Tenant-ID, and becomes a principal
// that holds nothing but certs:issue there. The resolver lives in the server,
// which owns the trust sources; the API owns the narrow door.

// AttestationPrincipalResolver turns a bearer proof into the identity a
// tenant's self-authenticating trust sources vouch for. It fails closed: no
// such source, a proof none of them verifies, or an owner outside the pin is
// an error, never an anonymous principal.
type AttestationPrincipalResolver interface {
	ResolveAttestedPrincipal(ctx context.Context, tenantID string, proof []byte) (AttestedPrincipal, error)
}

// AttestedPrincipal is the identity a verified proof established.
type AttestedPrincipal struct {
	// Subject is the principal's name, e.g. github:acme/payments.
	Subject string
	// Method is the attestation method that verified the proof.
	Method string
}

// WithAttestationPrincipalResolver enables the attestation-as-credential path.
// Without it a bearer that is not a trstctl API token is unauthenticated.
func WithAttestationPrincipalResolver(r AttestationPrincipalResolver) Option {
	return func(c *config) { c.attestationPrincipals = r }
}

// AttestedWorkloadRoleName names the single synthetic role a self-authenticated
// workload acts under. It is not registered in the role registry and cannot be
// granted to anyone: it exists only on the principal the resolver built.
const AttestedWorkloadRoleName = "attested-workload"

var attestedWorkloadRole = authz.Role{Name: AttestedWorkloadRoleName, Permissions: []authz.Permission{authz.CertsIssue}}

var errAttestationBearerNeedsTenant = errors.New("api: a self-authenticating attestation bearer requires X-Tenant-ID")

// attestedIssuanceRoute reports whether the request is one of the two routes a
// self-authenticating proof may open: the attested-issuance command and its
// effect-free preview. Everywhere else the proof is not a credential.
func attestedIssuanceRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/workloads/attested-issuance", "/api/v1/workloads/attested-issuance/preview":
		return true
	}
	return false
}

// resolveAttestationBearer builds the principal for a bearer that is not an
// API token. The tenant must be named by the caller: the proof carries no
// trstctl tenant, and guessing one from a repository name would let a token
// pick the tenant with the most permissive source.
func (a *API) resolveAttestationBearer(r *http.Request, proof []byte) (authz.Principal, error) {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		return authz.Principal{}, errAttestationBearerNeedsTenant
	}
	resolved, err := a.attestationPrincipals.ResolveAttestedPrincipal(r.Context(), tenantID, proof)
	if err != nil {
		return authz.Principal{}, err
	}
	if strings.TrimSpace(resolved.Subject) == "" {
		return authz.Principal{}, errors.New("api: attestation resolver returned an empty subject")
	}
	return authz.Principal{
		TenantID: tenantID, Subject: resolved.Subject,
		Grants: []authz.Grant{{Role: attestedWorkloadRole, Scope: authz.Scope{TenantID: tenantID}}},
	}, nil
}

// principalIsAttestedWorkload reports whether the request's principal was
// built from an attestation bearer rather than an API token or a session.
func principalIsAttestedWorkload(ctx context.Context) bool {
	p, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || len(p.Grants) != 1 {
		return false
	}
	return p.Grants[0].Role.Name == AttestedWorkloadRoleName
}

// requireAttestationBearerIsPayload binds the credential to the proof: a
// workload that authenticated with its own token must be asking for ITS
// certificate. Otherwise one admitted workflow could present another valid
// token as the payload and mint for a different repository under its own name
// in the audit trail.
func requireAttestationBearerIsPayload(r *http.Request, payload []byte) error {
	if !principalIsAttestedWorkload(r.Context()) {
		return nil
	}
	bearer := bearerTokenBytes(r)
	if len(bearer) == 0 || !crypto.ConstantTimeEqual(bearer, payload) {
		return errStatus(http.StatusForbidden, "a self-authenticating workflow must send the same OIDC token as the bearer credential and as payload_base64")
	}
	return nil
}
