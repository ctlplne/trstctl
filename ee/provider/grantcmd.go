// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	corestore "trstctl.com/trstctl/internal/store"
)

func RunGrantCommand(ctx context.Context, dsn string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("provider-grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		operator   = fs.String("operator", "", "operator id the grant is for")
		customer   = fs.String("customer", "", "customer tenant id the grant is over")
		operations = fs.String("operations", "", "comma-separated operations: read,provision,suspend,resume,offboard,break-glass")
		grantedBy  = fs.String("granted-by", "", "who issued this grant, recorded for audit")
		revoke     = fs.Bool("revoke", false, "remove the named grants instead of adding them")
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
	ops, err := parseDelegatedOperations(*operations)
	if err != nil {
		return err
	}

	st, err := corestore.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("provider-grant: open database: %w", err)
	}
	defer st.Close()
	src := NewPGDelegationSource(st)
	if src == nil {
		return fmt.Errorf("provider-grant: no database, so there is nowhere to record a grant")
	}

	if *revoke {
		for _, op := range ops {
			if err := src.Revoke(ctx, *operator, *customer, op); err != nil {
				return fmt.Errorf("provider-grant: revoke %s: %w", op, err)
			}
		}
		_, _ = fmt.Fprintf(stdout, "revoked %s on %s from %s\n", *operations, *customer, *operator)
		return nil
	}
	if err := src.Grant(ctx, Delegation{
		OperatorID: *operator, CustomerID: *customer, Operations: ops,
	}, *grantedBy); err != nil {
		return fmt.Errorf("provider-grant: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "granted %s on %s to %s\n", *operations, *customer, *operator)
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
