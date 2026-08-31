// SPDX-License-Identifier: MPL-2.0

package server

import (
	"errors"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

// workloadIdentityScope comes from authenticated server arguments and the
// verified attestation, never from proof claims selecting their own tenant.
// Separate routes prevent an ordinary attested request claiming an approved
// ephemeral identity or a broker's policy-authorized agent name.
type workloadIdentityScope struct {
	TenantID string
	Method   string
	Kind     string
	AgentID  string
}

// workloadSPIFFEID binds authority before appending any subject-controlled text.
// Its reserved prefix cannot be minted by ordinary CSR profiles or manual
// Workload API registration. The original readable subject remains unchanged
// in issuance responses, audit and history.
func workloadSPIFFEID(trustDomain string, scope workloadIdentityScope, subject string) (string, error) {
	domainID, err := crypto.ParseSPIFFEID("spiffe://" + strings.TrimSpace(trustDomain))
	if err != nil || domainID.Path != "" {
		return "", errors.New("a canonical SPIFFE trust domain without a path is required")
	}
	if subject == "" || len(subject) > crypto.MaxSPIFFEIDLength {
		return "", errors.New("attestation subject is empty or exceeds the identity size limit")
	}
	tenant, err := uuid.Parse(scope.TenantID)
	if err != nil || tenant == uuid.Nil || tenant.String() != scope.TenantID {
		return "", errors.New("a canonical authenticated tenant UUID is required for workload identity")
	}
	method, err := workloadIdentitySegment(scope.Method)
	if err != nil {
		return "", errors.New("a verified attestation method is required for workload identity")
	}
	id := domainID.String() + crypto.ReservedWorkloadSPIFFEPath + "/v1/tenant/" + scope.TenantID
	switch scope.Kind {
	case "broker":
		agent, err := workloadIdentitySegment(scope.AgentID)
		if err != nil {
			return "", errors.New("a policy-authorized agent ID is required for broker identity")
		}
		id += "/broker/agent/" + agent
	case "attested", "ephemeral":
		if scope.AgentID != "" {
			return "", errors.New("non-broker workload identity cannot carry a broker agent ID")
		}
		id += "/" + scope.Kind
	default:
		return "", errors.New("an explicit workload issuance route is required")
	}
	id += "/method/" + method + "/subject"
	for _, part := range strings.Split(subject, "/") {
		segment, err := workloadIdentitySegment(part)
		if err != nil {
			return "", err
		}
		if len(id)+1+len(segment) > crypto.MaxSPIFFEIDLength {
			return "", errors.New("mapped attestation subject exceeds the SPIFFE identity size limit")
		}
		id += "/" + segment
	}
	if _, err := crypto.ParseSPIFFEID(id); err != nil {
		return "", err
	}
	return id, nil
}

// Whole-segment encoding is injective: literal encoded-looking names are
// encoded too. Slashes in an agent ID or method cannot escape their field.
// Subject hierarchy is split before this helper; no empty/dot segment is cleaned.
func workloadIdentitySegment(segment string) (string, error) {
	return crypto.EncodeWorkloadSPIFFESegment(segment)
}

func ephemeralSPIFFEID(trustDomain, tenantID, method, subject string) (string, error) {
	return workloadSPIFFEID(trustDomain, workloadIdentityScope{TenantID: tenantID, Method: method, Kind: "ephemeral"}, subject)
}

// certificateSPIFFEID is presentation metadata, not an authorization decision.
// Read the actual leaf; never rebuild its identity from today's tenant, method
// or friendly subject. Older retained credentials can have noncanonical URI
// syntax. Keep their exact recovery behavior and leave this optional field
// unavailable instead of inventing an alias or relaxing the strict parser.
func certificateSPIFFEID(der []byte) string {
	id, err := crypto.SPIFFEIDFromCert(der)
	if err != nil {
		return ""
	}
	return id
}
