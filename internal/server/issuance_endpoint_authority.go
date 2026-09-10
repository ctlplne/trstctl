// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

type endpointAuthoritySelection struct {
	Source string
	ID     string
}

func endpointIssuingAuthority(raw json.RawMessage) (endpointAuthoritySelection, error) {
	selection := endpointAuthoritySelection{Source: "platform", ID: "trstctl-issuing-ca"}
	if len(raw) == 0 {
		return selection, nil
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return endpointAuthoritySelection{}, fmt.Errorf("server: decode identity issuing authority: %w", err)
	}
	source, sourceSet := attrs["issuing_authority_source"].(string)
	id, idSet := attrs["issuing_authority_id"].(string)
	source, id = strings.TrimSpace(source), strings.TrimSpace(id)
	if !sourceSet && !idSet {
		return selection, nil
	}
	if source == "" || id == "" {
		return endpointAuthoritySelection{}, errors.New("server: identity has an incomplete issuing authority selection; no CA was substituted")
	}
	switch source {
	case "platform":
		if id != "trstctl-issuing-ca" {
			return endpointAuthoritySelection{}, errors.New("server: identity names an unknown platform issuing authority; no CA was substituted")
		}
	case "private", "external":
	default:
		return endpointAuthoritySelection{}, errors.New("server: identity names an unsupported issuing authority source; no CA was substituted")
	}
	return endpointAuthoritySelection{Source: source, ID: id}, nil
}

func endpointBindingIssueKey(p transitionTrigger, message orchestrator.Message) string {
	if key := strings.TrimSpace(p.IdempotencyKey); key != "" {
		return "endpoint-binding:" + key
	}
	return "lifecycle:" + strings.TrimSpace(message.IdempotencyKey)
}

// issueEndpointCSR is the single CA-selection seam for endpoint enrollment and
// renewal. It never substitutes another authority: a missing, mismatched, or
// unsupported selection fails before its certificate can be accepted.
func (d *issuanceDispatcher) issueEndpointCSR(
	ctx context.Context,
	tenantID string,
	selection endpointAuthoritySelection,
	issueKey string,
	csrDER []byte,
	dnsNames []string,
	ttl time.Duration,
	leafProfile crypto.LeafProfile,
) (leafPEM, chainPEM []byte, caID, source string, err error) {
	switch selection.Source {
	case "platform":
		if d.issue == nil {
			return nil, nil, "", "", errors.New("server: selected platform issuing CA is unavailable; no CA was substituted")
		}
		leafPEM, err = d.issue(ctx, csrDER, ttl, leafProfile)
		return leafPEM, append([]byte(nil), d.chainPEM...), IssuingCAID(), "issued", err
	case "private":
		if d.authorityIssue == nil {
			return nil, nil, "", "", errors.New("server: selected private CA issuance is unavailable; no CA was substituted")
		}
		leafPEM, chainPEM, caID, err = d.authorityIssue(ctx, tenantID, selection.ID, csrDER, ttl, leafProfile)
		if err == nil && caID != selection.ID {
			return nil, nil, "", "", errors.New("server: selected private CA returned a different authority; no certificate was accepted")
		}
		return leafPEM, chainPEM, caID, "issued", err
	case "external":
		return d.issueEndpointCSRExternal(ctx, tenantID, selection.ID, issueKey, csrDER, dnsNames, ttl)
	default:
		return nil, nil, "", "", errors.New("server: unsupported endpoint issuing authority; no CA was substituted")
	}
}

func (d *issuanceDispatcher) issueEndpointCSRExternal(
	ctx context.Context,
	tenantID, authorityID, issueKey string,
	csrDER []byte,
	dnsNames []string,
	ttl time.Duration,
) (leafPEM, chainPEM []byte, caID, source string, err error) {
	if d.externalCAs == nil {
		return nil, nil, "", "", errors.New("server: selected external CA is unavailable; no CA was substituted")
	}
	issueKey = strings.TrimSpace(issueKey)
	if issueKey == "" {
		return nil, nil, "", "", errors.New("server: selected external CA issuance has no idempotency key")
	}
	bindingBody, marshalErr := json.Marshal(struct {
		Operation   string   `json:"operation"`
		TenantID    string   `json:"tenant_id"`
		AuthorityID string   `json:"authority_id"`
		IssueKey    string   `json:"issue_key"`
		CSRDER      []byte   `json:"csr_der"`
		DNSNames    []string `json:"dns_names"`
		TTLNanos    int64    `json:"ttl_nanos"`
	}{"endpoint-binding.issue", tenantID, authorityID, issueKey, csrDER, dnsNames, int64(ttl)})
	if marshalErr != nil {
		return nil, nil, "", "", marshalErr
	}
	defer secret.Wipe(bindingBody)
	issued, issueErr := d.externalCAs.IssueExternalCA(ctx, tenantID, authorityID, issueKey,
		crypto.SHA256Hex(bindingBody), api.ExternalCAIssueRequest{
			CSRDER: append([]byte(nil), csrDER...), DNSNames: append([]string(nil), dnsNames...), TTLSeconds: int64(ttl / time.Second),
		})
	if issueErr != nil {
		return nil, nil, "", "", issueErr
	}
	block, rest := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, "", "", errors.New("server: selected external CA returned no leaf certificate")
	}
	return pem.EncodeToMemory(block), append([]byte(nil), rest...), "", "issued", nil
}
