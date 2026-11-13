// SPDX-License-Identifier: BUSL-1.1

package digicert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
)

// WithDCVPublisher lets the plugin complete CertCentral's DNS TXT domain
// validation with no human step (A165): orders ask for the dns-txt-token
// method, the plugin publishes the order's random value at _dnsauth.<name> for
// every requested name through p, asks CertCentral to check, and retracts the
// records on every exit. Without a publisher, orders behave as before and
// validation is completed in the DigiCert console.
func WithDCVPublisher(p ca.TXTPublisher) Option {
	return func(b *backend) { b.dcv = p }
}

// validateDomains publishes the order's DCV records, asks CertCentral to check
// them, and retracts them before returning.
func (b *backend) validateDomains(ctx context.Context, tenantID string, orderID int, dnsNames []string, randomValue string) (err error) {
	if strings.TrimSpace(randomValue) == "" {
		return errors.New("digicert: the order carried no DCV random value to publish")
	}
	var retractions []func(context.Context) error
	defer func() {
		for _, retract := range retractions {
			if rerr := retract(context.WithoutCancel(ctx)); rerr != nil {
				err = errors.Join(err, fmt.Errorf("digicert: retract DCV record: %w", rerr))
			}
		}
	}()
	// A165-L3: CertCentral validates a wildcard's base name, so the record
	// goes there, but the publisher is told the name is a wildcard so its
	// wildcard policy and CAA issuewild apply.
	bases, wildcard := ca.DCVBaseNames(dnsNames)
	seen := map[string]bool{}
	for _, name := range bases {
		seen[name] = true
		identifier := name
		if wildcard[name] {
			identifier = "*." + name
		}
		retract, perr := b.dcv.PublishTXT(ctx, tenantID, identifier, "_dnsauth."+name, randomValue)
		if perr != nil {
			return fmt.Errorf("digicert: publish the DCV record for %s: %w", identifier, perr)
		}
		if retract != nil {
			retractions = append(retractions, retract)
		}
	}
	// A165-L4: asked until CertCentral sees the records or the validation
	// budget runs out, the checks spaced further apart as they go.
	deadline := time.Now().Add(b.dcvTimeout)
	for attempt := 0; ; attempt++ {
		var checked struct {
			DCVStatus   string `json:"dcv_status"`
			OrderStatus string `json:"order_status"`
		}
		if err := b.do(ctx, http.MethodPut, b.orderURL(strconv.Itoa(orderID)+"/check-dcv"), map[string]any{}, &checked); err != nil {
			return fmt.Errorf("digicert: check DCV: %w", err)
		}
		if checked.DCVStatus == "complete" || checked.OrderStatus == "issued" {
			// A165-L2: every name this order published for is validated now.
			for name := range seen {
				ca.ObserveDomainValidation(ctx, b.dcv, tenantID, ca.DomainValidation{Identifier: name, Method: ca.DomainValidationMethodDNSTXT})
			}
			return nil
		}
		wait := ca.DCVBackoff(b.poll, attempt)
		if time.Now().Add(wait).After(deadline) {
			return fmt.Errorf("digicert: CertCentral has not seen the DCV records within %s; domain validation did not complete", b.dcvTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
