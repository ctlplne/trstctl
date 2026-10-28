// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/netsec"
)

// CMDBCertificateExportBinding is a separate opt-in write authority. Ownership
// readers and ticket writers never acquire this authority from their bindings.
type CMDBCertificateExportBinding struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	Enabled              bool     `json:"enabled"`
	InstanceURL          string   `json:"instance_url"`
	TokenRef             string   `json:"token_ref"`
	DataSource           string   `json:"data_source"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

var cmdbExportBindingID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidateCMDBCertificateExports also protects direct server.Build callers.
func ValidateCMDBCertificateExports(bindings []CMDBCertificateExportBinding) []error {
	var errs []error
	seen := map[string]bool{}
	for i, binding := range bindings {
		name := fmt.Sprintf("itsm.servicenow.certificate_exports[%d]", i)
		id, err := uuid.Parse(binding.TenantID)
		if err != nil || id == uuid.Nil {
			errs = append(errs, fmt.Errorf("%s.tenant_id must be a non-empty tenant UUID", name))
		}
		key := id.String() + ":" + binding.ID
		if !cmdbExportBindingID.MatchString(binding.ID) || seen[key] {
			errs = append(errs, fmt.Errorf("%s.id must be unique per tenant and contain 1-64 lowercase letters, digits, underscores or hyphens", name))
		}
		seen[key] = true
		if _, err := cmdbexport.Endpoint(binding.InstanceURL, binding.DataSource); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		if !strings.HasPrefix(binding.TokenRef, "secret://") && !strings.HasPrefix(binding.TokenRef, "file:") {
			errs = append(errs, fmt.Errorf("%s.token_ref must use a secret:// reference or a file: reference", name))
		}
		if binding.AllowPrivateEndpoint != (len(binding.PrivateEgressCIDRs) > 0) {
			errs = append(errs, fmt.Errorf("%s private endpoint access requires allow_private_endpoint and exact private_egress_cidrs together", name))
		}
		for _, raw := range binding.PrivateEgressCIDRs {
			if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
				errs = append(errs, fmt.Errorf("%s.private_egress_cidrs: %w", name, err))
			}
		}
	}
	return errs
}
