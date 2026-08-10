// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

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
		customer   = fs.String("customer", "", "customer tenant id the grant is over")
		operations = fs.String("operations", "", "comma-separated operations: read,provision,suspend,resume,offboard,break-glass")
		grantedBy  = fs.String("granted-by", "", "who issued this grant, recorded for audit")
		revoke     = fs.Bool("revoke", false, "remove the named grants instead of adding them")
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

	st, err := corestore.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("provider-grant: open database: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("provider-grant: migrate database: %w", err)
	}
	log, err := events.Open(ctx, natsConfig,
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
			OperatorID: strings.TrimSpace(*operator), CustomerID: strings.TrimSpace(*customer),
			Operation: op, GrantedBy: strings.TrimSpace(*grantedBy),
		})
	}
	bindingBytes, err := json.Marshal(struct {
		Operator, Customer, Operations, GrantedBy string
		Revoke                                    bool
	}{
		Operator: strings.TrimSpace(*operator), Customer: strings.TrimSpace(*customer),
		Operations: strings.TrimSpace(*operations), GrantedBy: strings.TrimSpace(*grantedBy),
		Revoke: *revoke,
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
	if _, err := runtime.Mutations.Append(ctx, strings.TrimSpace(*idemKey), typ, strings.TrimSpace(*customer),
		AuthorityEvent{Delegations: mutations, EffectiveAt: now,
			Audit: AuditEvent{Type: typ, TenantID: strings.TrimSpace(*customer),
				OperatorID: strings.TrimSpace(*grantedBy), Subject: "provider-grant", At: now}}); err != nil {
		return fmt.Errorf("provider-grant: %w", err)
	}
	preposition := "to"
	if *revoke {
		preposition = "from"
	}
	_, _ = fmt.Fprintf(stdout, "%s %s on %s %s %s\n", verb, *operations, *customer, preposition, *operator)
	return nil
}

// parseDelegatedOperations refuses anything outside the closed vocabulary.
//
// A typo'd operation that were accepted would store a grant that authorises
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
			"authorises nothing, and storing one would put a row in the table that reads like access")
	}
	return out, nil
}
