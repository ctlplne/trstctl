// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/netsec"
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

// ADCSInventoryIntent is the shared reference-only job payload.
type ADCSInventoryIntent = adcs.InventoryIntent

// ADCSReport is what the relay returns.
type ADCSReport = adcs.InventoryReport

// adcsDialTimeout bounds the connection. A domain controller that does not
// answer promptly is one an operator needs told about, not waited on.
const adcsDialTimeout = 20 * time.Second

type adcsHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type agentRestrictionObserver func(context.Context, adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions

// ldapSearcher adapts a live LDAP connection to the adcs package's read-only
// interface. It exposes Search and nothing else — the connection's mutating
// methods are not reachable through this type.
type ldapSearcher struct{ conn *ldap.Conn }

const ldapServerSDFlagsOID = "1.2.840.113556.1.4.801"

// ldapSearchControls returns the exact Microsoft control that asks for only the
// DACL portion of nTSecurityDescriptor. Without it a default AD search may ask
// for owner/group/SACL too, which is more privilege and data than this reader
// needs. The value is BER(SEQUENCE(INTEGER(0x4))).
func ldapSearchControls(request adcs.SearchRequest) []ldap.Control {
	if !request.DACLOnly {
		return nil
	}
	return []ldap.Control{&ldap.ControlString{
		ControlType:  ldapServerSDFlagsOID,
		Criticality:  true,
		ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
	}}
}

func (l ldapSearcher) Search(ctx context.Context, request adcs.SearchRequest) ([]adcs.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.MaxEntries <= 0 || request.MaxEntries > adcs.MaxTemplates {
		return nil, errors.New("relay: AD CS LDAP search has an invalid entry bound")
	}
	req := ldap.NewSearchRequest(
		request.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		request.MaxEntries, int(adcsDialTimeout.Seconds()), false,
		request.Filter, request.Attributes, ldapSearchControls(request),
	)
	res, err := l.conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]adcs.Entry, 0, len(res.Entries))
	for _, entry := range res.Entries {
		attrs := make(map[string][]string, len(entry.Attributes))
		binaryAttrs := make(map[string][][]byte, 1)
		for _, a := range entry.Attributes {
			if strings.EqualFold(a.Name, "nTSecurityDescriptor") {
				values := make([][]byte, 0, len(a.ByteValues))
				for _, value := range a.ByteValues {
					values = append(values, append([]byte(nil), value...))
				}
				binaryAttrs["nTSecurityDescriptor"] = values
				continue
			}
			attrs[a.Name] = append([]string(nil), a.Values...)
		}
		out = append(out, adcs.Entry{DN: entry.DN, Attributes: attrs, BinaryAttributes: binaryAttrs})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// InventoryADCS reads one domain's template posture.
func InventoryADCS(ctx context.Context, intent ADCSInventoryIntent, material Material) (ADCSReport, error) {
	if intent.DryRun {
		return ADCSReport{}, errors.New("relay: AD CS inventory is already read-only and does not support dry-run")
	}
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
	if len(inventory.Templates) == 0 {
		return ADCSReport{}, errors.New("relay: AD CS directory returned no templates")
	}
	endpointClient, err := newADCSEndpointClient(intent)
	if err != nil {
		return ADCSReport{}, err
	}
	if err := enrichADCSInventory(ctx, intent, &inventory, endpointClient, observeCAAgentRestrictions); err != nil {
		return ADCSReport{}, err
	}
	report := ADCSReport{
		Status:            "succeeded",
		Inventory:         inventory,
		Findings:          adcs.Findings(inventory),
		DirectoryVerified: !intent.InsecureSkipVerify,
	}
	if err := adcs.ValidateInventoryReport(intent, report); err != nil {
		return ADCSReport{}, err
	}
	return report, nil
}

func newADCSEndpointClient(intent ADCSInventoryIntent) (*http.Client, error) {
	prefixes, err := intent.PrivateEgressPrefixes()
	if err != nil {
		return nil, fmt.Errorf("relay: invalid AD CS endpoint egress boundary: %w", err)
	}
	client := netsec.SafeClientWithOptions(adcsDialTimeout, netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("relay: AD CS endpoint client has an unexpected safe transport")
	}
	// Keep the resolved-address SSRF dialer while routing TLS policy through the
	// crypto boundary. Redirects are evidence, not instructions: following one
	// could leave the exact operator-scoped endpoint and erase its real status.
	transport.TLSClientConfig = mtls.DirectoryClientTLSConfig(false)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func enrichADCSInventory(
	ctx context.Context,
	intent ADCSInventoryIntent,
	inventory *adcs.Inventory,
	client adcsHTTPDoer,
	restrictions agentRestrictionObserver,
) error {
	if inventory == nil || client == nil || restrictions == nil {
		return errors.New("relay: AD CS live-evidence collector is incomplete")
	}
	services := make(map[string]*adcs.EnrollmentService, len(inventory.EnrollmentServices))
	for i := range inventory.EnrollmentServices {
		service := &inventory.EnrollmentServices[i]
		services[service.Name] = service
		service.AgentRestrictions = restrictions(ctx, *service)
		if service.AgentRestrictions.State == "" || strings.TrimSpace(service.AgentRestrictions.Source) == "" {
			service.AgentRestrictions = adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "ca_policy_collector_failed_closed"}
		}
	}
	for _, target := range intent.EnrollmentEndpoints {
		service := services[target.EnrollmentService]
		if service == nil {
			return fmt.Errorf("relay: configured enrollment endpoint names unknown service %q", target.EnrollmentService)
		}
		service.Endpoints = append(service.Endpoints, observeEnrollmentEndpoint(ctx, client, target))
	}
	for i := range inventory.EnrollmentServices {
		sort.Slice(inventory.EnrollmentServices[i].Endpoints, func(a, b int) bool {
			left, right := inventory.EnrollmentServices[i].Endpoints[a], inventory.EnrollmentServices[i].Endpoints[b]
			if left.Kind != right.Kind {
				return left.Kind < right.Kind
			}
			return left.URL < right.URL
		})
	}
	return nil
}

func observeEnrollmentEndpoint(ctx context.Context, client adcsHTTPDoer, target adcs.EnrollmentEndpointTarget) adcs.EnrollmentEndpoint {
	observed := adcs.EnrollmentEndpoint{
		Kind: target.Kind, URL: target.URL, State: adcs.EndpointUnreachable,
		ExtendedProtection: adcs.EvidenceUnobserved,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return observed
	}
	// A range makes a cooperative server send only one byte. A server that
	// ignores it is still safe because the body is closed without being read.
	req.Header.Set("Range", "bytes=0-0")
	response, err := client.Do(req)
	if err != nil {
		return observed
	}
	defer response.Body.Close()
	observed.HTTPStatus = response.StatusCode
	observed.TLSVerified = strings.HasPrefix(strings.ToLower(target.URL), "https://")
	observed.Authentication = authenticationSchemes(response.Header.Values("WWW-Authenticate"))
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		observed.State = adcs.EndpointAnonymousAccess
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		observed.State = adcs.EndpointAuthenticationNeeded
	case response.StatusCode >= 300 && response.StatusCode < 400:
		observed.State = adcs.EndpointRedirected
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone:
		observed.State = adcs.EndpointNotFound
	default:
		observed.State = adcs.EndpointReachableOther
	}
	return observed
}

func authenticationSchemes(headers []string) []string {
	allowed := map[string]string{
		"basic": "Basic", "digest": "Digest", "negotiate": "Negotiate",
		"ntlm": "NTLM", "bearer": "Bearer",
	}
	seen := map[string]bool{}
	for _, header := range headers {
		for _, part := range strings.Split(header, ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) == 0 {
				continue
			}
			if normalized, ok := allowed[strings.ToLower(fields[0])]; ok {
				seen[normalized] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for scheme := range seen {
		out = append(out, scheme)
	}
	sort.Strings(out)
	return out
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
		// local. The signed semantic report carries only a closed code; transport
		// outcome is executed because the relay did execute this read attempt.
		adcsReport = ADCSReport{Status: "failed", ErrorCode: "directory_read_failed"}
	}
	detail, err := json.Marshal(adcsReport)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "AD CS inventory could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
