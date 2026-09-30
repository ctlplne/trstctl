// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
)

// sshKRLWatchOptions describes an opt-in host-local pull loop. The public KRL
// carries no credentials. TLS pins the control plane, and its tenant header
// must match the operator's intended tenant before any host file is touched.
type sshKRLWatchOptions struct {
	Enabled           bool
	Confirm           bool
	URL               string
	CAFile            string
	ServerName        string
	TenantID          string
	AllowPrivateCIDRs []netip.Prefix
	PollEvery         time.Duration
	TargetPath        string
	SSHDConfigPath    string
	RollbackDir       string
	ReloadCmd         string
	HealthCmd         string
}

func runSSHKRLWatch(ctx context.Context, o sshKRLWatchOptions, checks sshkrl.Checks) (bool, error) {
	if !o.Enabled {
		return false, nil
	}
	if !o.Confirm {
		return true, errors.New("--ssh-krl-watch changes this host's active revocation list; review the tenant, target, health probe, and rollback path, then use --ssh-krl-confirm")
	}
	client, err := newSSHKRLWatchClient(o)
	if err != nil {
		return true, err
	}
	if o.TenantID == "" || o.TargetPath == "" || o.SSHDConfigPath == "" || o.RollbackDir == "" || o.ReloadCmd == "" || o.HealthCmd == "" {
		return true, errors.New("--ssh-krl-watch requires tenant, target, sshd config, rollback directory, reload command, and known-good login health command")
	}
	if !filepath.IsAbs(o.TargetPath) || !filepath.IsAbs(o.SSHDConfigPath) || !filepath.IsAbs(o.RollbackDir) {
		return true, errors.New("--ssh-krl-watch requires absolute target, sshd config, and rollback paths")
	}
	if _, err := parseCommandLine(o.ReloadCmd); err != nil {
		return true, fmt.Errorf("invalid --ssh-krl-reload-cmd: %w", err)
	}
	if _, err := parseCommandLine(o.HealthCmd); err != nil {
		return true, fmt.Errorf("invalid --ssh-krl-health-cmd: %w", err)
	}
	if o.PollEvery < 5*time.Second {
		return true, errors.New("--ssh-krl-watch-every must be at least 5s")
	}
	for {
		result, syncErr := syncSSHKRLOnce(ctx, client, o, checks)
		if ctx.Err() != nil {
			return true, nil
		}
		if syncErr != nil {
			fmt.Fprintln(os.Stderr, "trstctl-agent: SSH KRL sync failed; retained the last installed list:", syncErr)
		} else if result.Changed {
			fmt.Printf("trstctl-agent: SSH KRL automatically updated from version %d to %d (sha256 %s); predecessor at %s\n", result.PreviousVersion, result.Version, result.SHA256, result.RollbackPath)
		}
		timer := time.NewTimer(o.PollEvery)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return true, nil
		case <-timer.C:
		}
	}
}

func newSSHKRLWatchClient(o sshKRLWatchOptions) (*http.Client, error) {
	u, err := url.Parse(strings.TrimSpace(o.URL))
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/ssh/krl" || u.RawPath != "" {
		return nil, errors.New("--ssh-krl-url must be an exact https://host/ssh/krl URL without credentials, query, or redirect")
	}
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: o.AllowPrivateCIDRs}
	if err := netsec.ValidatePublicHTTPSURLWithOptions(o.URL, opts); err != nil {
		return nil, fmt.Errorf("--ssh-krl-url: %w", err)
	}
	if o.CAFile == "" {
		return nil, errors.New("--ca-bundle is required for --ssh-krl-watch")
	}
	caPEM, err := os.ReadFile(o.CAFile) // #nosec G304 -- operator-selected CA bundle for this exact HTTPS origin
	if err != nil {
		return nil, fmt.Errorf("read SSH KRL control-plane CA: %w", err)
	}
	tlsTransport, err := mtls.AgentHTTPTransport(nil, caPEM, o.ServerName, nil)
	if err != nil {
		return nil, fmt.Errorf("SSH KRL TLS trust: %w", err)
	}
	client := netsec.SafeClientWithOptions(15*time.Second, opts)
	safeTransport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("SSH KRL safe HTTP transport is unavailable")
	}
	safeTransport.TLSClientConfig = tlsTransport.TLSClientConfig
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("SSH KRL endpoint redirected; exact origin required")
	}
	return client, nil
}

func syncSSHKRLOnce(ctx context.Context, client *http.Client, o sshKRLWatchOptions, checks sshkrl.Checks) (sshkrl.Result, error) {
	if client == nil || checks == nil {
		return sshkrl.Result{}, errors.New("SSH KRL sync requires an HTTP client and local OpenSSH checks")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		return sshkrl.Result{}, fmt.Errorf("build SSH KRL request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return sshkrl.Result{}, fmt.Errorf("fetch SSH KRL over verified HTTPS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return sshkrl.Result{}, fmt.Errorf("SSH KRL endpoint returned HTTP %d; retained installed list", resp.StatusCode)
	}
	if resp.Header.Get("X-Trstctl-Tenant-ID") != o.TenantID || o.TenantID == "" {
		return sshkrl.Result{}, errors.New("SSH KRL response tenant does not match the configured tenant")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return sshkrl.Result{}, errors.New("SSH KRL response is not an OpenSSH binary artifact")
	}
	const maxBytes = 128 << 20
	if resp.ContentLength > maxBytes {
		return sshkrl.Result{}, errors.New("SSH KRL response exceeds the bounded size")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return sshkrl.Result{}, errors.New("SSH KRL response is unreadable or exceeds the bounded size")
	}
	return sshkrl.Apply(ctx, sshkrl.Config{
		TargetPath: o.TargetPath, SSHDConfigPath: o.SSHDConfigPath,
		RollbackDir: o.RollbackDir, Checks: checks, SkipReloadOnUnchanged: true,
	}, data, crypto.SHA256Hex(data))
}

func parseKRLPrivateCIDRs(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 16 {
		return nil, errors.New("--ssh-krl-allow-private-cidrs accepts at most 16 ranges")
	}
	out := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netsec.ParseEgressAllowPrefix(part)
		if err != nil {
			return nil, fmt.Errorf("--ssh-krl-allow-private-cidrs: %w", err)
		}
		out = append(out, prefix)
	}
	return out, nil
}
