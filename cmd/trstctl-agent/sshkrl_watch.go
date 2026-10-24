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
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
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
	// Receipts, when set, holds each attempt's receipt for an enrolled host
	// agent to sign onto its heartbeat (A109).
	Receipts *sshKRLReceipts
}

func runSSHKRLWatch(ctx context.Context, o sshKRLWatchOptions, checks sshkrl.Checks) (bool, error) {
	if !o.Enabled {
		return false, nil
	}
	client, err := prepareSSHKRLWatch(o)
	if err != nil {
		return true, err
	}
	watchSSHKRL(ctx, client, o, checks)
	return true, nil
}

// prepareSSHKRLWatch checks every watcher option and builds its pinned client
// before the first poll, so a misconfigured watcher stops at startup.
func prepareSSHKRLWatch(o sshKRLWatchOptions) (*http.Client, error) {
	if !o.Confirm {
		return nil, errors.New("--ssh-krl-watch changes this host's active revocation list; review the tenant, target, health probe, and rollback path, then use --ssh-krl-confirm")
	}
	client, err := newSSHKRLWatchClient(o)
	if err != nil {
		return nil, err
	}
	if o.TenantID == "" || o.TargetPath == "" || o.SSHDConfigPath == "" || o.RollbackDir == "" || o.ReloadCmd == "" || o.HealthCmd == "" {
		return nil, errors.New("--ssh-krl-watch requires tenant, target, sshd config, rollback directory, reload command, and known-good login health command")
	}
	if !filepath.IsAbs(o.TargetPath) || !filepath.IsAbs(o.SSHDConfigPath) || !filepath.IsAbs(o.RollbackDir) {
		return nil, errors.New("--ssh-krl-watch requires absolute target, sshd config, and rollback paths")
	}
	if _, err := parseCommandLine(o.ReloadCmd); err != nil {
		return nil, fmt.Errorf("invalid --ssh-krl-reload-cmd: %w", err)
	}
	if _, err := parseCommandLine(o.HealthCmd); err != nil {
		return nil, fmt.Errorf("invalid --ssh-krl-health-cmd: %w", err)
	}
	if o.PollEvery < 5*time.Second {
		return nil, errors.New("--ssh-krl-watch-every must be at least 5s")
	}
	return client, nil
}

// watchSSHKRL polls until ctx ends. Each attempt's receipt, read back from
// the installed file, goes to o.Receipts when an enrolled agent reports them.
func watchSSHKRL(ctx context.Context, client *http.Client, o sshKRLWatchOptions, checks sshkrl.Checks) {
	for {
		result, receipt, syncErr := attemptSSHKRL(ctx, client, o, checks, time.Now)
		if ctx.Err() != nil {
			return
		}
		o.Receipts.record(receipt)
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
			return
		case <-timer.C:
		}
	}
}

// sshKRLAgentWatch runs the KRL watcher beside an enrolled host agent (A109).
// It is checked before enrollment and started once, after the agent's
// certificate shows the host role, and it outlives certificate rotations.
type sshKRLAgentWatch struct {
	options  sshKRLWatchOptions
	checks   sshkrl.Checks
	client   *http.Client
	once     sync.Once
	issuedAt atomic.Int64
}

func newSSHKRLAgentWatch(o sshKRLWatchOptions, checks sshkrl.Checks) (*sshKRLAgentWatch, error) {
	client, err := prepareSSHKRLWatch(o)
	if err != nil {
		return nil, err
	}
	o.Receipts = &sshKRLReceipts{}
	return &sshKRLAgentWatch{options: o, checks: checks, client: client}, nil
}

func (w *sshKRLAgentWatch) start(ctx context.Context) {
	w.once.Do(func() { go watchSSHKRL(ctx, w.client, w.options, w.checks) })
}

// sshKRLReceipts holds this host's newest KRL receipt (A109) for the enrolled
// agent's heartbeat. A nil holder records nothing: the standalone watcher has
// no channel to report on.
type sshKRLReceipts struct {
	latest      atomic.Pointer[sshkrlreceipt.Receipt]
	installedAt atomic.Int64
}

// Latest is the newest receipt, or nil before the first readable one.
func (r *sshKRLReceipts) Latest() *sshkrlreceipt.Receipt {
	if r == nil {
		return nil
	}
	return r.latest.Load()
}

func (r *sshKRLReceipts) record(receipt *sshkrlreceipt.Receipt) {
	if r == nil || receipt == nil {
		return
	}
	next := *receipt
	if next.Outcome == sshkrlreceipt.OutcomeInstalled {
		r.installedAt.Store(next.CheckedAtUnix)
	}
	next.InstalledAtUnix = r.installedAt.Load()
	r.latest.Store(&next)
}

// attemptSSHKRL fetches and applies the served list once, then accounts for
// the attempt in a receipt whose installed digest and version are read back
// from the RevokedKeys file sshd uses. The receipt is nil when that file
// cannot be read as a KRL.
func attemptSSHKRL(ctx context.Context, client *http.Client, o sshKRLWatchOptions, checks sshkrl.Checks, now func() time.Time) (sshkrl.Result, *sshkrlreceipt.Receipt, error) {
	fetched, fetchErr := fetchSSHKRL(ctx, client, o)
	var result sshkrl.Result
	err := fetchErr
	if fetchErr == nil {
		result, err = applySSHKRL(ctx, o, checks, fetched)
	}
	return result, sshKRLReceiptFor(o, fetched, fetchErr, result, err, now()), err
}

func sshKRLReceiptFor(o sshKRLWatchOptions, fetched []byte, fetchErr error, result sshkrl.Result, applyErr error, now time.Time) *sshkrlreceipt.Receipt {
	installed, err := os.ReadFile(o.TargetPath) // #nosec G304 -- the operator's absolute RevokedKeys path, read back for the receipt
	if err != nil {
		return nil
	}
	installedVersion, err := sshkrl.Version(installed)
	if err != nil {
		return nil
	}
	receipt := &sshkrlreceipt.Receipt{
		KRLTenantID: o.TenantID, InstalledVersion: installedVersion, InstalledSHA256: crypto.SHA256Hex(installed),
		CheckedAtUnix: now.UTC().Unix(), PollEverySeconds: int64(o.PollEvery / time.Second),
	}
	if fetchErr != nil {
		receipt.Outcome = sshkrlreceipt.OutcomeFetchFailed
		return receipt
	}
	receipt.FetchedSHA256 = crypto.SHA256Hex(fetched)
	receipt.FetchedVersion, _ = sshkrl.Version(fetched)
	var drop *sshkrl.DropError
	switch {
	case applyErr == nil && receipt.FetchedSHA256 == receipt.InstalledSHA256:
		receipt.Outcome = sshkrlreceipt.OutcomeCurrent
		if result.Changed {
			receipt.Outcome = sshkrlreceipt.OutcomeInstalled
		}
	case errors.As(applyErr, &drop):
		receipt.Outcome = sshkrlreceipt.OutcomeRefusedDropsRevocations
		receipt.DroppedSerials, receipt.DroppedKeyIDs = drop.Serials, drop.KeyIDs
		receipt.DroppedKeys, receipt.DroppedKeyHashes = drop.Keys, drop.Fingerprints
	case errors.Is(applyErr, sshkrl.ErrNotNewer):
		receipt.Outcome = sshkrlreceipt.OutcomeRefusedNotNewer
	default:
		// A failed check, a rollback, or a file that does not hold what was
		// applied: the host does not enforce the fetched list.
		receipt.Outcome = sshkrlreceipt.OutcomeApplyFailed
	}
	return receipt
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
	data, err := fetchSSHKRL(ctx, client, o)
	if err != nil {
		return sshkrl.Result{}, err
	}
	return applySSHKRL(ctx, o, checks, data)
}

// fetchSSHKRL downloads the served list over the pinned client and checks
// that it is an OpenSSH binary artifact for the configured tenant.
func fetchSSHKRL(ctx context.Context, client *http.Client, o sshKRLWatchOptions) ([]byte, error) {
	if client == nil {
		return nil, errors.New("SSH KRL sync requires an HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build SSH KRL request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch SSH KRL over verified HTTPS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SSH KRL endpoint returned HTTP %d; retained installed list", resp.StatusCode)
	}
	if resp.Header.Get("X-Trstctl-Tenant-ID") != o.TenantID || o.TenantID == "" {
		return nil, errors.New("SSH KRL response tenant does not match the configured tenant")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		return nil, errors.New("SSH KRL response is not an OpenSSH binary artifact")
	}
	const maxBytes = 128 << 20
	if resp.ContentLength > maxBytes {
		return nil, errors.New("SSH KRL response exceeds the bounded size")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("SSH KRL response is unreadable or exceeds the bounded size")
	}
	return data, nil
}

func applySSHKRL(ctx context.Context, o sshKRLWatchOptions, checks sshkrl.Checks, data []byte) (sshkrl.Result, error) {
	if checks == nil {
		return sshkrl.Result{}, errors.New("SSH KRL sync requires local OpenSSH checks")
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
