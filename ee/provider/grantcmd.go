// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

func RunGrantCommand(ctx context.Context, dsn string, natsConfig config.NATS, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("provider-grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		operator   = fs.String("operator", "", "operator id the grant is for")
		customer   = fs.String("customer", "", "customer the grant is over: the tenant id, or the customer slug you will provision (its id is derived from the slug and printed)")
		operations = fs.String("operations", "", "comma-separated operations: read,provision,suspend,resume,offboard,break-glass")
		grantedBy  = fs.String("granted-by", "", "who issued this grant, recorded for audit")
		revoke     = fs.Bool("revoke", false, "remove the named grants instead of adding them")
		expiresAt  = fs.String("expires-at", "", "optional RFC3339 time after which the grant no longer authorizes anything (grants only)")
		idemKey    = fs.String("idempotency-key", "", "required stable key; identical retry returns the original authority event")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: trstctl provider-grant -operator ID -customer TENANT -operations read,suspend\n\n"+
			"Grants a provider operator authority over one customer. There is deliberately no\n"+
			"wildcard customer: a wildcard grant is indistinguishable from the unscoped access\n"+
			"this mechanism replaces.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*operator) == "" || strings.TrimSpace(*customer) == "" {
		fs.Usage()
		return fmt.Errorf("provider-grant: both -operator and -customer are required; a grant " +
			"naming only one side reads like access somebody has")
	}
	if strings.TrimSpace(*idemKey) == "" {
		fs.Usage()
		return fmt.Errorf("provider-grant: -idempotency-key is required; provider authority mutations may not bypass AN-5")
	}
	ops, err := parseDelegatedOperations(*operations)
	if err != nil {
		return err
	}
	var expiry time.Time
	if strings.TrimSpace(*expiresAt) != "" {
		if *revoke {
			return errors.New("provider-grant: -expires-at applies to a grant, not a revoke")
		}
		parsed, perr := time.Parse(time.RFC3339, strings.TrimSpace(*expiresAt))
		if perr != nil {
			return fmt.Errorf("provider-grant: -expires-at must be RFC3339: %w", perr)
		}
		expiry = parsed
	}
	customerID, derived := ResolveCustomerRef(*customer)

	st, err := corestore.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("provider-grant: open database: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("provider-grant: migrate database: %w", err)
	}
	// This offline command does not own the persistent audit signer required to
	// rewrite history. Its constructor therefore installs the live v1 floor and
	// refuses to replay until the central server has completed AUD-116 sanitation.
	log, err := events.OpenRequiringSanitizedSchedulerHistory(ctx, natsConfig,
		events.WithRequiredPrivacyEventPolicies(),
		events.WithHistoryRewriteCoordinator(corestore.NewHistoryRewriteCoordinator(st)))
	if err != nil {
		return fmt.Errorf("provider-grant: open event log (run this offline when using embedded NATS): %w", err)
	}
	defer func() { _ = log.Close() }()
	runtime := NewAuthorityRuntime(st, log)
	if err := runtime.Bootstrap(ctx); err != nil {
		return fmt.Errorf("provider-grant: bootstrap authority history: %w", err)
	}
	mutations := make([]DelegationMutation, 0, len(ops))
	for _, op := range ops {
		mutations = append(mutations, DelegationMutation{
			OperatorID: strings.TrimSpace(*operator), CustomerID: customerID,
			Operation: op, GrantedBy: strings.TrimSpace(*grantedBy), ExpiresAt: expiry,
		})
	}
	bindingBytes, err := json.Marshal(struct {
		Operator, Customer, Operations, GrantedBy, ExpiresAt string
		Revoke                                               bool
	}{
		Operator: strings.TrimSpace(*operator), Customer: customerID,
		Operations: strings.TrimSpace(*operations), GrantedBy: strings.TrimSpace(*grantedBy),
		ExpiresAt: strings.TrimSpace(*expiresAt), Revoke: *revoke,
	})
	if err != nil {
		return err
	}
	ctx = contextWithMutationBinding(ctx, "sha256:"+crypto.SHA256Hex(bindingBytes))
	typ, verb := EventDelegationGranted, "granted"
	if *revoke {
		typ, verb = EventDelegationRevoked, "revoked"
	}
	now := time.Now().UTC()
	if _, err := runtime.Mutations.Append(ctx, strings.TrimSpace(*idemKey), typ, customerID,
		AuthorityEvent{Delegations: mutations, EffectiveAt: now,
			Audit: AuditEvent{Type: typ, TenantID: customerID,
				OperatorID: strings.TrimSpace(*grantedBy), Subject: "provider-grant", At: now}}); err != nil {
		return fmt.Errorf("provider-grant: %w", err)
	}
	preposition := "to"
	if *revoke {
		preposition = "from"
	}
	if derived {
		_, _ = fmt.Fprintf(stdout, "%s %s on customer %s (id %s, derived from the slug) %s %s\n", verb, *operations, strings.TrimSpace(*customer), customerID, preposition, *operator)
	} else {
		_, _ = fmt.Fprintf(stdout, "%s %s on %s %s %s\n", verb, *operations, customerID, preposition, *operator)
	}
	return nil
}

// ResolveCustomerRef turns the operator's -customer value into the customer
// tenant id the provider plane authorizes against. A customer does not exist
// before it is provisioned, and its id is derived deterministically from its
// slug (CustomerID), so a grant may name the slug the operator is about to
// provision; a value that already is a uuid is used as given. The second
// result reports whether the id was derived.
func ResolveCustomerRef(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if _, err := uuid.Parse(value); err == nil {
		return strings.ToLower(value), false
	}
	return CustomerID(value), true
}

// parseDelegatedOperations refuses anything outside the closed vocabulary.
//
// A typo'd operation that were accepted would store a grant that authorizes
// nothing, and the operator would see "granted" and later be refused with no
// way to connect the two.
func parseDelegatedOperations(raw string) ([]Operation, error) {
	fields := strings.Split(raw, ",")
	known := map[Operation]bool{}
	for _, op := range Operations {
		known[op] = true
	}
	var out []Operation
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		op := Operation(f)
		if !known[op] {
			return nil, fmt.Errorf("provider-grant: %q is not a delegable operation; the set is %v",
				f, Operations)
		}
		out = append(out, op)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provider-grant: -operations is required. A grant with no operations " +
			"authorizes nothing, and storing one would put a row in the table that reads like access")
	}
	return out, nil
}
