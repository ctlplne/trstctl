// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/supportbundle"
)

func runSupportBundle(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trstctl support-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "output .tar.gz path (default: timestamped file in the current directory)")
	logFile := fs.String("log-file", "", "optional local log file; only a bounded, secret/PII-redacted tail is included")
	includeEnrollmentDiagnostics := fs.Bool("include-enrollment-diagnostics", false, "fetch an authorized aggregate enrollment-diagnostic addendum using TRSTCTL_URL and TRSTCTL_TOKEN")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("support-bundle: unexpected argument %q", fs.Arg(0))
	}
	var diagnostics *supportbundle.EnrollmentDiagnosticsAddendum
	if *includeEnrollmentDiagnostics {
		fetched, err := fetchEnrollmentDiagnosticsAddendum(ctx, getenv)
		if err != nil {
			return err
		}
		diagnostics = &fetched
	}
	path, err := supportbundle.Create(ctx, supportbundle.Options{
		Getenv: getenv, Output: *output, LogFile: *logFile, EnrollmentDiagnostics: diagnostics,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote redacted support bundle to %s\n", path)
	return nil
}

func fetchEnrollmentDiagnosticsAddendum(ctx context.Context, getenv func(string) string) (supportbundle.EnrollmentDiagnosticsAddendum, error) {
	baseURL := strings.TrimSpace(getenv("TRSTCTL_URL"))
	token := strings.TrimSpace(getenv("TRSTCTL_TOKEN"))
	if baseURL == "" || token == "" {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: --include-enrollment-diagnostics requires TRSTCTL_URL and TRSTCTL_TOKEN")
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: TRSTCTL_URL must be an HTTP(S) origin without credentials, query, or path")
	}
	if base.Scheme == "http" && base.Hostname() != "localhost" {
		ip := net.ParseIP(base.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: TRSTCTL_URL requires HTTPS except for a loopback development origin")
		}
	}
	endpoint := base.ResolveReference(&url.URL{Path: "/api/v1/enrollment/diagnostics/support-addendum"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: build diagnostic addendum request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client, err := supportBundleDiagnosticClient(ctx, endpoint)
	if err != nil {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: fetch diagnostic addendum failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, fmt.Errorf("support-bundle: diagnostic addendum returned HTTP %d", response.StatusCode)
	}
	const maxAddendumBytes = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAddendumBytes+1))
	if err != nil || len(raw) > maxAddendumBytes {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: diagnostic addendum is unreadable or too large")
	}
	var addendum supportbundle.EnrollmentDiagnosticsAddendum
	if err := json.Unmarshal(raw, &addendum); err != nil {
		return supportbundle.EnrollmentDiagnosticsAddendum{}, errors.New("support-bundle: diagnostic addendum is invalid JSON")
	}
	return addendum, nil
}

func supportBundleDiagnosticClient(ctx context.Context, endpoint *url.URL) (*http.Client, error) {
	if endpoint == nil {
		return nil, errors.New("support-bundle: diagnostic addendum endpoint is missing")
	}
	var client *http.Client
	if netsec.IsInsecureLoopbackHTTPURL(endpoint.String()) {
		client = netsec.InsecureLoopbackClient(10 * time.Second)
	} else {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", endpoint.Hostname())
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("support-bundle: resolve diagnostic addendum origin failed")
		}
		options := netsec.SafeClientOptions{}
		for _, address := range addresses {
			address = address.Unmap()
			// A self-hosted control plane often has an RFC-1918/ULA address. Pin
			// only the exact address DNS returned now; the guarded dialer resolves
			// again and rejects any other private address. Hard-blocked metadata,
			// link-local, multicast, and CGNAT ranges remain blocked by netsec.
			if address.IsPrivate() || address.IsLoopback() {
				options.AllowPrivateCIDRs = append(options.AllowPrivateCIDRs,
					netip.PrefixFrom(address, address.BitLen()))
			}
		}
		client = netsec.SafeClientWithOptions(10*time.Second, options)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not accepted for diagnostic addenda")
	}
	return client, nil
}
