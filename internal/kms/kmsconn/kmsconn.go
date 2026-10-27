// SPDX-License-Identifier: BUSL-1.1

// Package kmsconn is what a process needs before it talks to a cloud KMS or an
// HSM: endpoint validation, an egress-guarded HTTP client, and credential files
// read into locked memory. The isolated signer's managed-key providers and
// trstctl-kms-wrap, the signer's key-store wrap adapter, build their provider
// clients with it, so both enforce the same egress and credential rules.
package kmsconn

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// requestTimeout bounds one provider HTTP exchange.
const requestTimeout = 30 * time.Second

// ValidateEndpoints accepts each non-empty endpoint over HTTPS, or over HTTP on
// loopback when allowInsecureLoopback is set; setting allowInsecureLoopback
// without such an endpoint is a configuration error. label names the client in
// errors, for example "aws managed-key".
func ValidateEndpoints(label string, allowInsecureLoopback bool, endpoints ...string) error {
	usedInsecureLoopback := false
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint) == "" {
			continue
		}
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
			return fmt.Errorf("%s endpoint: %w", label, err)
		}
		usedInsecureLoopback = usedInsecureLoopback || netsec.IsInsecureLoopbackHTTPURL(endpoint)
	}
	if allowInsecureLoopback && !usedInsecureLoopback {
		return fmt.Errorf("%s allow_insecure_loopback requires an HTTP localhost/loopback endpoint", label)
	}
	return nil
}

// EgressClient is the HTTP client a provider client uses: plaintext only to an
// allowed loopback endpoint, otherwise HTTPS through the SSRF-guarded client,
// which reaches private addresses only inside rawCIDRs and re-checks every
// redirect.
func EgressClient(rawCIDRs []string, endpoint string, allowInsecureLoopback bool) (*http.Client, error) {
	allowPlaintext := allowInsecureLoopback && netsec.IsInsecureLoopbackHTTPURL(endpoint)
	if strings.TrimSpace(endpoint) != "" {
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowPlaintext); err != nil {
			return nil, err
		}
	}
	if allowPlaintext {
		return netsec.InsecureLoopbackClient(requestTimeout), nil
	}
	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid private egress CIDR %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}
	client := netsec.SafeClientWithOptions(requestTimeout, netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes})
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req == nil || req.URL == nil {
			return fmt.Errorf("provider redirect is missing a URL")
		}
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(req.URL.String(), false); err != nil {
			return err
		}
		return previousRedirect(req, via)
	}
	return client, nil
}

// CredentialFile reads a credential file (a cloud token, an access key, an HSM
// PIN) into locked memory and returns it with the function that wipes it. An
// empty path is an error when required and nothing otherwise; an empty file is
// an error when required.
func CredentialFile(name, file string, required bool) ([]byte, func(), error) {
	if strings.TrimSpace(file) == "" {
		if required {
			return nil, func() {}, fmt.Errorf("%s file is required", name)
		}
		return nil, func() {}, nil
	}
	raw, err := readCredentialFile(file)
	if err != nil {
		return nil, func() {}, fmt.Errorf("read %s file: %w", name, err)
	}
	return lockCredentialBytes(name, raw, required)
}

// readCredentialFile reads a credential through a handle on its parent
// directory instead of by name. These files carry authority-bearing material,
// so a symlink swapped in at the final component must not be able to redirect
// the read somewhere else between the operator's configuration and the open.
// os.Root resolves every component at the syscall layer and refuses one that
// leaves the directory (CWE-22, CWE-367).
func readCredentialFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}

func lockCredentialBytes(name string, fileBuffer []byte, required bool) ([]byte, func(), error) {
	// bytes.TrimSpace returns a subslice. Clone the useful payload first, then
	// wipe the complete read allocation so bytes outside that subslice do not
	// remain in the heap.
	payload := bytes.Clone(bytes.TrimSpace(fileBuffer))
	secret.Wipe(fileBuffer)
	if required && len(payload) == 0 {
		secret.Wipe(payload)
		return nil, func() {}, fmt.Errorf("%s file is empty", name)
	}
	locked, err := secret.NewFrom(payload)
	secret.Wipe(payload)
	if err != nil {
		return nil, func() {}, fmt.Errorf("lock %s: %w", name, err)
	}
	return locked.Bytes(), locked.Destroy, nil
}
