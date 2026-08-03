// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/adcs"
)

// AD CS template inventory from inside the domain (epic F1).
//
// This has to run on a relay, and not because of a policy choice. A domain
// controller's LDAP service is not reachable from a hosted control plane, and it
// should not be — an organization that exposed 389 to the internet has a larger
// problem than certificate management. An in-domain relay is the only vantage
// from which this inventory exists at all.
//
// It reads. The LDAP connection is used for Search and nothing else, the
// adcs.Searcher interface it satisfies has exactly one method, and a test in
// the adcs package asserts that. An inventory tool pointed at a domain
// controller must be structurally incapable of modifying one.

// KindADCSInventory is the job kind for a template sweep.
const KindADCSInventory = "adcs.inventory"

// ADCSInventoryIntent is the job payload.
type ADCSInventoryIntent struct {
	// URL is the directory to read, ldap:// or ldaps://. StartTLS is used on a
	// plain ldap:// URL, because a template inventory carries the map of a
	// domain's escalation paths and reading it in the clear would publish that
	// map to anyone on the segment.
	URL string `json:"url"`
	// ConfigurationDN is the forest configuration naming context. It is required
	// rather than derived from the domain, because a forest root and a domain
	// are not the same thing and guessing gets it wrong in exactly the
	// multi-domain estates where this matters most.
	ConfigurationDN string `json:"configuration_dn"`
	// BindDN and the credential reference authenticate the read. Anonymous LDAP
	// is refused: it usually fails against a hardened DC anyway, and where it
	// succeeds it means the directory is misconfigured in a way worth reporting
	// rather than quietly relying on.
	BindDN string `json:"bind_dn"`
	// PasswordRef names the credential the relay redeems for this attempt, the
	// same way a connector deploy does. The value never travels in this payload.
	PasswordRef string `json:"password_ref"`
	// InsecureSkipVerify is a lab escape hatch for a DC using a self-signed
	// certificate. It is off by default and reported in the result, so an
	// inventory taken without verifying the directory's identity is never
	// mistaken for one taken with it.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// ADCSReport is what the relay returns.
type ADCSReport struct {
	Inventory adcs.Inventory `json:"inventory"`
	Findings  []adcs.Finding `json:"findings"`
	// DirectoryVerified reports whether the directory's TLS identity was
	// checked. A template inventory taken over an unverified connection is
	// weaker evidence and says so rather than reading identically.
	DirectoryVerified bool `json:"directory_verified"`
}

// adcsDialTimeout bounds the connection. A domain controller that does not
// answer promptly is one an operator needs told about, not waited on.
const adcsDialTimeout = 20 * time.Second

// ldapSearcher adapts a live LDAP connection to the adcs package's read-only
// interface. It exposes Search and nothing else — the connection's mutating
// methods are not reachable through this type.
type ldapSearcher struct{ conn *ldap.Conn }

func (l ldapSearcher) Search(_ context.Context, baseDN, filter string, attributes []string) ([]adcs.Entry, error) {
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(adcsDialTimeout.Seconds()), false,
		filter, attributes, nil,
	)
	res, err := l.conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]adcs.Entry, 0, len(res.Entries))
	for _, entry := range res.Entries {
		attrs := make(map[string][]string, len(entry.Attributes))
		for _, a := range entry.Attributes {
			attrs[a.Name] = a.Values
		}
		out = append(out, adcs.Entry{DN: entry.DN, Attributes: attrs})
	}
	return out, nil
}

// InventoryADCS reads one domain's template posture.
func InventoryADCS(ctx context.Context, intent ADCSInventoryIntent, material Material) (ADCSReport, error) {
	url := strings.TrimSpace(intent.URL)
	if url == "" {
		return ADCSReport{}, errors.New("relay: AD CS inventory needs a directory URL")
	}
	if strings.TrimSpace(intent.BindDN) == "" || strings.TrimSpace(intent.PasswordRef) == "" {
		// Anonymous reads are refused rather than attempted. Where they succeed
		// the directory is misconfigured in a way worth reporting, and relying
		// on that silently would hide it.
		return ADCSReport{}, errors.New("relay: AD CS inventory needs a bind DN and a credential reference; anonymous directory reads are not attempted")
	}
	password, ok := material[strings.TrimSpace(intent.PasswordRef)]
	if !ok || len(password) == 0 {
		return ADCSReport{}, errors.New("relay: the directory bind credential was not redeemed for this attempt")
	}

	// The TLS policy comes from the crypto boundary (AN-3): this package never
	// names crypto/tls, it obtains the configured value and hands it to the
	// LDAP library.
	tlsConfig := mtls.DirectoryClientTLSConfig(intent.InsecureSkipVerify)
	conn, err := ldap.DialURL(url,
		ldap.DialWithDialer(&net.Dialer{Timeout: adcsDialTimeout}),
		ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return ADCSReport{}, fmt.Errorf("relay: connect to the directory: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if strings.HasPrefix(strings.ToLower(url), "ldap://") {
		// A template inventory is the map of a domain's escalation paths.
		// Reading it in the clear publishes that map to anyone on the segment,
		// so a plain connection is upgraded or the read does not happen.
		if err := conn.StartTLS(tlsConfig); err != nil {
			return ADCSReport{}, fmt.Errorf("relay: the directory would not start TLS, and this inventory is not read in the clear: %w", err)
		}
	}
	if err := conn.Bind(intent.BindDN, string(password)); err != nil {
		return ADCSReport{}, fmt.Errorf("relay: directory bind failed: %w", err)
	}

	inventory, err := adcs.Collect(ctx, ldapSearcher{conn: conn}, intent.ConfigurationDN)
	if err != nil {
		return ADCSReport{}, err
	}
	return ADCSReport{
		Inventory:         inventory,
		Findings:          adcs.Findings(inventory),
		DirectoryVerified: !intent.InsecureSkipVerify,
	}, nil
}

// runADCSInventory executes an adcs.inventory job.
func runADCSInventory(ctx context.Context, ch Channel, job Job, material Material) bool {
	var intent ADCSInventoryIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not an AD CS inventory intent")
		return false
	}
	adcsReport, err := InventoryADCS(ctx, intent, material)
	if err != nil {
		// The directory's own error text can name accounts and DNs. It stays
		// local; the control plane gets a closed phrase and the operator reads
		// the detail on the relay.
		report(ctx, ch, job, OutcomeFailed, "the AD CS inventory could not be read from this relay")
		return false
	}
	detail, err := json.Marshal(adcsReport)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "AD CS inventory could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
