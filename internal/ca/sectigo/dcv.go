// SPDX-License-Identifier: BUSL-1.1

package sectigo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
)

// WithDCVPublisher lets the plugin complete SCM's DNS TXT domain control
// validation with no human step (A165): before enrolling, it starts a TXT
// validation for every requested name, publishes the record SCM names through
// p, submits it, waits for SCM to report the domain validated, and retracts the
// record. Without a publisher, validation is completed in Sectigo's console.
func WithDCVPublisher(p ca.TXTPublisher) Option {
	return func(b *backend) { b.dcv = p }
}

const (
	dcvBase   = "/api/dcv/v1/validation"
	dcvChecks = 10
)

// validateDomains runs SCM's TXT validation for every requested name.
func (b *backend) validateDomains(ctx context.Context, tenantID string, dnsNames []string) error {
	// A165-L3: SCM validates a wildcard's base name; the publisher is told
	// the name is a wildcard so its wildcard policy and CAA issuewild apply.
	bases, wildcard := ca.DCVBaseNames(dnsNames)
	for _, name := range bases {
		if err := b.validateDomain(ctx, tenantID, name, wildcard[name]); err != nil {
			return err
		}
	}
	return nil
}

func (b *backend) validateDomain(ctx context.Context, tenantID, domain string, wildcard bool) (err error) {
	var status struct {
		Status string `json:"status"`
	}
	if err := b.postJSON(ctx, b.cfg.BaseURL+dcvBase+"/status", map[string]string{"domain": domain}, &status); err != nil {
		return fmt.Errorf("sectigo: DCV status of %s: %w", domain, err)
	}
	if strings.EqualFold(status.Status, "VALIDATED") {
		// A165-L2: SCM already held the domain validated; nothing was published.
		ca.ObserveDomainValidation(ctx, b.dcv, tenantID, ca.DomainValidation{Identifier: domain, Reused: true})
		return nil
	}
	var started struct {
		Host  string `json:"host"`
		Point string `json:"point"`
	}
	if err := b.postJSON(ctx, b.cfg.BaseURL+dcvBase+"/start/domain/txt", map[string]string{"domain": domain}, &started); err != nil {
		return fmt.Errorf("sectigo: start DCV for %s: %w", domain, err)
	}
	if strings.TrimSpace(started.Host) == "" || strings.TrimSpace(started.Point) == "" {
		return fmt.Errorf("sectigo: DCV for %s named no TXT record to publish", domain)
	}
	identifier := domain
	if wildcard {
		identifier = "*." + domain
	}
	retract, err := b.dcv.PublishTXT(ctx, tenantID, identifier, strings.TrimSuffix(started.Host, "."), started.Point)
	if err != nil {
		return fmt.Errorf("sectigo: publish the DCV record for %s: %w", domain, err)
	}
	if retract != nil {
		defer func() {
			if rerr := retract(context.WithoutCancel(ctx)); rerr != nil {
				err = errors.Join(err, fmt.Errorf("sectigo: retract DCV record: %w", rerr))
			}
		}()
	}
	if err := b.postJSON(ctx, b.cfg.BaseURL+dcvBase+"/submit/domain/txt", map[string]string{"domain": domain}, nil); err != nil {
		return fmt.Errorf("sectigo: submit DCV for %s: %w", domain, err)
	}
	for attempt := 0; attempt < dcvChecks; attempt++ {
		if err := b.postJSON(ctx, b.cfg.BaseURL+dcvBase+"/status", map[string]string{"domain": domain}, &status); err != nil {
			return fmt.Errorf("sectigo: DCV status of %s: %w", domain, err)
		}
		if strings.EqualFold(status.Status, "VALIDATED") {
			ca.ObserveDomainValidation(ctx, b.dcv, tenantID, ca.DomainValidation{Identifier: domain, Method: ca.DomainValidationMethodDNSTXT})
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.poll):
		}
	}
	return fmt.Errorf("sectigo: SCM has not validated %s; domain validation did not complete", domain)
}
