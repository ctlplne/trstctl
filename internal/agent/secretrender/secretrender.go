// SPDX-License-Identifier: BUSL-1.1

// Package secretrender renders control-plane secrets into files for an
// application (A238). Each template is literal text with {{ secret "name" }}
// placeholders, rendered over bytes: a value is never turned into a string, never
// logged, and its buffer is wiped once written. A file is written atomically (a
// private temporary file in the same directory, flushed, given its mode, then
// renamed over the old one), the template's reload hook runs, and its verify
// probe asks the application to prove it uses the new values. The control plane
// hears "injected" when the file is written and "verified" only when the probe
// passes. When the control plane can't be reached the last file keeps serving
// until the freshness bound, then is removed (or kept, if the template says so);
// the bound survives a restart because the fetch time is kept in a state file
// that holds no values.
package secretrender

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

// Config is the renderer's configuration file.
type Config struct {
	Server    string `yaml:"server" json:"server"`
	CAFile    string `yaml:"ca_file" json:"ca_file"`
	TokenFile string `yaml:"token_file" json:"token_file"`
	// LoginMethod and LoginCredentialFile sign the renderer in as its
	// workload instead of TokenFile (A238-L1): the credential (a service
	// account token, a cloud identity token) is exchanged at the tenant's
	// machine auth method for a session.
	LoginMethod         string        `yaml:"login_method" json:"login_method"`
	LoginCredentialFile string        `yaml:"login_credential_file" json:"login_credential_file"`
	Tenant              string        `yaml:"tenant" json:"tenant"`
	Consumer            string        `yaml:"consumer" json:"consumer"`
	Interval            time.Duration `yaml:"interval" json:"interval"`
	Freshness           time.Duration `yaml:"freshness" json:"freshness"`
	StateDir            string        `yaml:"state_dir" json:"state_dir"`
	Templates           []Template    `yaml:"templates" json:"templates"`
}

// Template is one rendered file.
type ReplacementBootstrap struct {
	ChangeID string `yaml:"change_id" json:"change_id"`
	Provider string `yaml:"provider" json:"provider"`
	Role     string `yaml:"role" json:"role"`
}

// ReplacementPublication contains only public metadata from an approved change.
type ReplacementPublication struct {
	ID, State, Action, Consumer, Provider, Role, LeaseID, NativeRoleID string
	Version, ExpectedVersion                                           int
	ExpiresAt                                                          time.Time
}

// ReplacementReader reads the publication whose exact version the consumer must use.
type ReplacementReader interface {
	ReadReplacement(context.Context, string) (ReplacementPublication, error)
}

type Template struct {
	Replacement *ReplacementBootstrap `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	Name        string                `yaml:"name" json:"name"`
	Destination string                `yaml:"destination" json:"destination"`
	// Mode is the file's octal permission bits; 0400 when empty.
	Mode string `yaml:"mode" json:"mode"`
	// Owner and Group give the file to an application's user and group, as
	// names or numeric IDs (A238-L2). They need the agent to run as root and
	// are not served on Windows, where the file's DACL names who reads it.
	Owner  string `yaml:"owner" json:"owner"`
	Group  string `yaml:"group" json:"group"`
	Text   string `yaml:"template" json:"template"`
	Reload Hook   `yaml:"reload" json:"reload"`
	Verify Verify `yaml:"verify" json:"verify"`
	// OnStale is what happens when the freshness bound passes without reaching
	// the control plane: remove (the default) or keep.
	OnStale string `yaml:"on_stale" json:"on_stale"`
	// LeaseTTL is the lifetime asked for each dynamic lease the template uses;
	// one hour when zero.
	LeaseTTL time.Duration `yaml:"lease_ttl" json:"lease_ttl"`
}

// Hook reloads the application after a write: an argv run with no shell, or a
// signal to the process named by a pid file.
type Hook struct {
	Command []string `yaml:"command" json:"command"`
	Signal  string   `yaml:"signal" json:"signal"`
	PIDFile string   `yaml:"pid_file" json:"pid_file"`
}

// Verify asks the application to prove it uses the rendered values: an HTTP GET
// that must answer ExpectStatus, with basic auth whose password is a secret.
type Verify struct {
	URL            string        `yaml:"url" json:"url"`
	Username       string        `yaml:"username" json:"username"`
	PasswordSecret string        `yaml:"password_secret" json:"password_secret"`
	ExpectStatus   int           `yaml:"expect_status" json:"expect_status"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
}

// Fetcher reads a secret's current value and version.
type Fetcher interface {
	Fetch(ctx context.Context, name string) (value []byte, version int, err error)
}

// Reporter tells the control plane what a consumer wrote or verified.
type Reporter interface {
	Report(ctx context.Context, consumer, state string, versions map[string]int) error
}

// Lease is a dynamic credential as issued; Credential is returned only here.
type Lease struct {
	ID            string
	Credential    []byte
	ExpiresAt     time.Time
	HardExpiresAt time.Time
}

// LeaseClient issues, renews and revokes dynamic leases. key makes an issue
// idempotent: a retry with the same key returns the same lease.
type LeaseClient interface {
	IssueLease(ctx context.Context, provider, role string, ttl time.Duration, key string) (Lease, error)
	RenewLease(ctx context.Context, id string, extend time.Duration, key string) (time.Time, error)
	RevokeLease(ctx context.Context, id, key string) error
}

const (
	defaultInterval  = 30 * time.Second
	defaultFreshness = time.Hour
	stateRemove      = "remove"
	stateKeep        = "keep"
)

var (
	placeholder      = regexp.MustCompile(`^\{\{\s*secret\s+"([^"]{1,512})"\s*\}\}`)
	leasePlaceholder = regexp.MustCompile(`^\{\{\s*lease\s+"([A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127})"(?:\s+"([A-Za-z0-9_.-]{1,64})")?\s*\}\}`)
)

type segment struct {
	literal []byte
	secret  string
	lease   string // "provider/role"
	field   string // a JSON field of the lease credential; empty for all of it
}

// parseTemplate splits text into literal bytes and placeholders: only
// {{ secret "name" }} and {{ lease "provider/role" "field" }} are supported, so
// a template can't run code.
func parseTemplate(text string) ([]segment, []string, []string, error) {
	var segs []segment
	var names, leases []string
	rest := text
	for {
		idx := strings.Index(rest, "{{")
		if idx < 0 {
			if rest != "" {
				segs = append(segs, segment{literal: []byte(rest)})
			}
			break
		}
		if idx > 0 {
			segs = append(segs, segment{literal: []byte(rest[:idx])})
		}
		if m := placeholder.FindStringSubmatch(rest[idx:]); m != nil {
			segs = append(segs, segment{secret: m[1]})
			if !slices.Contains(names, m[1]) {
				names = append(names, m[1])
			}
			rest = rest[idx+len(m[0]):]
			continue
		}
		if m := leasePlaceholder.FindStringSubmatch(rest[idx:]); m != nil {
			segs = append(segs, segment{lease: m[1], field: m[2]})
			if !slices.Contains(leases, m[1]) {
				leases = append(leases, m[1])
			}
			rest = rest[idx+len(m[0]):]
			continue
		}
		return nil, nil, nil, errors.New(`secretrender: only {{ secret "name" }} and {{ lease "provider/role" "field" }} placeholders are supported`)
	}
	return segs, names, leases, nil
}

// Validate checks a configuration before anything runs.
func (c *Config) Validate() error {
	switch {
	case c.Server == "" || c.Consumer == "" || c.StateDir == "":
		return errors.New("secretrender: server, consumer and state_dir are required")
	case (c.TokenFile == "") == (c.LoginMethod == "" && c.LoginCredentialFile == ""):
		return errors.New("secretrender: give either token_file or login_method with login_credential_file")
	case c.TokenFile == "" && (c.LoginMethod == "" || c.LoginCredentialFile == ""):
		return errors.New("secretrender: login_method and login_credential_file go together")
	case len(c.Templates) == 0:
		return errors.New("secretrender: at least one template is required")
	}
	seen := map[string]bool{}
	for _, t := range c.Templates {
		if t.Name == "" || seen[t.Name] || !filepath.IsAbs(t.Destination) {
			return fmt.Errorf("secretrender: template %q needs a unique name and an absolute destination", t.Name)
		}
		seen[t.Name] = true
		if _, _, refs, err := parseTemplate(t.Text); err != nil {
			return fmt.Errorf("template %s: %w", t.Name, err)
		} else if t.Replacement != nil {
			b := t.Replacement
			if len(b.ChangeID) != 36 || b.Provider == "" || b.Role == "" || len(refs) != 1 || refs[0] != b.Provider+"/"+b.Role || t.Verify.URL == "" {
				return errors.New("secretrender: replacement needs a change UUID, matching single provider/role lease and an application verification probe")
			}
		}
		if _, err := t.mode(); err != nil {
			return err
		}
		if _, err := t.ownership(); err != nil {
			return err
		}
		if t.OnStale != "" && t.OnStale != stateRemove && t.OnStale != stateKeep {
			return fmt.Errorf("secretrender: template %s on_stale is remove or keep", t.Name)
		}
		if len(t.Reload.Command) > 0 && t.Reload.Signal != "" {
			return fmt.Errorf("secretrender: template %s reloads with a command or a signal, not both", t.Name)
		}
		if t.Reload.Signal != "" && (!signalKnown(t.Reload.Signal) || t.Reload.PIDFile == "") {
			return fmt.Errorf("secretrender: template %s signal is HUP, USR1, USR2 or TERM with a pid_file", t.Name)
		}
	}
	return nil
}

func (t Template) mode() (os.FileMode, error) {
	if t.Mode == "" {
		return 0o400, nil
	}
	v, err := strconv.ParseUint(t.Mode, 8, 32)
	if err != nil || v > 0o777 || v&0o007 != 0 {
		return 0, fmt.Errorf("secretrender: template %s mode %q must be octal with no access for others", t.Name, t.Mode)
	}
	return os.FileMode(v), nil
}

func signalKnown(name string) bool {
	switch strings.TrimPrefix(strings.ToUpper(name), "SIG") {
	case "HUP", "USR1", "USR2", "TERM":
		return true
	}
	return false
}

// templateState is what the renderer keeps between runs: versions and times,
// never values.
type templateState struct {
	ReplacementChangeID string                `json:"replacement_change_id,omitempty"`
	Versions            map[string]int        `json:"versions"`
	FetchedAt           time.Time             `json:"fetched_at"`
	WrittenAt           time.Time             `json:"written_at"`
	Verified            bool                  `json:"verified"`
	Removed             bool                  `json:"removed,omitempty"`
	Leases              map[string]leaseState `json:"leases,omitempty"`
	// Retire lists replaced leases, revoked once the application verified
	// their replacement.
	Retire []string `json:"retire,omitempty"`
}

// leaseState is a lease the file uses: never its credential. IssueKey is set
// before an issue call, so a retry after a crash gets the same lease back.
type leaseState struct {
	BootstrapName    string    `json:"bootstrap_name,omitempty"`
	BootstrapVersion int       `json:"bootstrap_version,omitempty"`
	ID               string    `json:"id,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
	IssueKey         string    `json:"issue_key,omitempty"`
}

// Renderer keeps a configuration's files current.
type Renderer struct {
	cfg    Config
	fetch  Fetcher
	report Reporter
	leases LeaseClient
	logger *slog.Logger
	now    func() time.Time
	held   heldLeases
}

// UseLeases lets the renderer issue, renew and revoke dynamic leases.
func (r *Renderer) UseLeases(c LeaseClient) { r.leases = c }

// New builds a renderer from a validated configuration.
func New(cfg Config, fetch Fetcher, report Reporter, logger *slog.Logger) (*Renderer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.Freshness <= 0 {
		cfg.Freshness = defaultFreshness
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Renderer{cfg: cfg, fetch: fetch, report: report, logger: logger, now: time.Now}, nil
}

// Run reconciles every template now and then on each interval until ctx ends;
// it destroys the lease credentials it holds when it returns.
func (r *Renderer) Run(ctx context.Context) error {
	defer r.Close()
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		r.Once(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close destroys the lease credentials the renderer holds in locked memory.
// A renderer used after Close issues fresh leases when it next writes a file.
func (r *Renderer) Close() { r.held.destroyAll() }

// Once reconciles every template once.
func (r *Renderer) Once(ctx context.Context) {
	for _, t := range r.cfg.Templates {
		if err := r.reconcile(ctx, t); err != nil {
			r.logger.Warn("secret template not reconciled", slog.String("template", t.Name), slog.String("error", err.Error()))
		}
	}
}

func (r *Renderer) statePath(t Template) string {
	return filepath.Join(r.cfg.StateDir, t.Name+".json")
}

func (r *Renderer) loadState(t Template) templateState {
	var st templateState
	raw, err := os.ReadFile(r.statePath(t)) // #nosec G304 -- the renderer's own state directory and a validated template name (CWE-22)
	if err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

func (r *Renderer) saveState(t Template, st templateState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(r.statePath(t), raw, 0o600, nil)
}

func (r *Renderer) reconcile(ctx context.Context, t Template) error {
	segs, names, leaseRefs, err := parseTemplate(t.Text)
	if err != nil {
		return err
	}
	if len(leaseRefs) > 0 && r.leases == nil {
		return errors.New("secretrender: the template uses leases but no lease client is configured")
	}
	st := r.loadState(t)
	if err := r.prepareReplacement(ctx, t, &st); err != nil {
		return r.stale(ctx, t, st, err)
	}
	values := map[string][]byte{}
	defer func() {
		for name, v := range values {
			secret.Wipe(v)
			delete(values, name)
		}
	}()
	versions := map[string]int{}
	wanted := slices.Clone(names)
	if t.Verify.PasswordSecret != "" && !slices.Contains(wanted, t.Verify.PasswordSecret) {
		wanted = append(wanted, t.Verify.PasswordSecret)
	}
	for _, name := range wanted {
		value, version, err := r.fetch.Fetch(ctx, name)
		if err != nil {
			return r.stale(ctx, t, st, err)
		}
		values[name] = value
		versions[name] = version
	}
	now := r.now()
	st.FetchedAt = now
	_, statErr := os.Stat(t.Destination)
	rendered := map[string]int{}
	for _, name := range names {
		rendered[name] = versions[name]
	}
	for _, ref := range leaseRefs {
		if ls := st.Leases[ref]; ls.BootstrapName != "" {
			rendered[ls.BootstrapName] = ls.BootstrapVersion
		}
	}
	ttl := t.LeaseTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	// A lease is renewed in place while it can be; one that can't be renewed
	// far enough is replaced. A file written again keeps every other lease: its
	// credential is held in locked memory from its issue (A238-L4). A lease
	// whose credential isn't held (a restarted renderer) is replaced when the
	// file is written, since a credential is returned only at issue, and one
	// whose issue answer was lost is issued again under its saved key.
	r.held.keep(t.Name, leaseRefs)
	replace := map[string]bool{}
	for _, ref := range leaseRefs {
		ls := st.Leases[ref]
		if ls.ID == "" || ls.IssueKey != "" {
			replace[ref] = true
			continue
		}
		if ls.BootstrapName != "" && !st.Verified {
			if !now.Before(ls.ExpiresAt) {
				return r.stale(ctx, t, st, errors.New("approved session expired before application verification"))
			}
			continue
		}
		if ls.ExpiresAt.Sub(now) > ttl/3 {
			continue
		}
		if exp, err := r.leases.RenewLease(ctx, ls.ID, ttl, ls.ID+"/renew/"+now.UTC().Format(time.RFC3339)); err == nil && exp.Sub(now) > ttl/3 {
			ls.ExpiresAt = exp
			st.Leases[ref] = ls
			continue
		}
		replace[ref] = true
	}
	staticChanged := !maps.Equal(rendered, st.Versions) || statErr != nil || st.Removed
	if !staticChanged && len(replace) == 0 {
		if !st.Verified && t.Verify.URL != "" && r.verify(ctx, t, values) == nil {
			st.Verified = true
			r.reportQuietly(ctx, t, "verified", rendered)
		}
		if st.Verified && t.Replacement != nil && len(rendered) > 0 {
			// Retrying this immutable report also recovers a lost HTTP response.
			r.reportQuietly(ctx, t, "verified", rendered)
		}
		if st.Verified || t.Verify.URL == "" {
			r.retireLeases(ctx, t, &st)
		}
		return r.saveState(t, st)
	}
	leaseValues := map[string][]byte{}
	defer func() {
		for ref, v := range leaseValues {
			secret.Wipe(v)
			delete(leaseValues, ref)
		}
	}()
	if len(leaseRefs) > 0 {
		if st.Leases == nil {
			st.Leases = map[string]leaseState{}
		}
		for _, ref := range leaseRefs {
			ls := st.Leases[ref]
			if ls.BootstrapName != "" && (!st.Verified || ls.ExpiresAt.Sub(now) > ttl/3) {
				lease, err := r.fetchReplacement(ctx, ls)
				if err != nil {
					return err
				}
				leaseValues[ref] = lease.Credential
				continue
			}
			if !replace[ref] && ls.BootstrapName == "" {
				if held := r.held.get(t.Name, ref, ls.ID); held != nil {
					leaseValues[ref] = held
					continue
				}
			}
			lease, err := r.issueLease(ctx, t, &st, ref, ttl)
			if err != nil {
				return err
			}
			if ls.BootstrapName != "" {
				delete(rendered, ls.BootstrapName)
			}
			if !r.held.put(t.Name, ref, lease.ID, lease.Credential) {
				r.logger.Warn("a lease credential could not be held in locked memory; the next rewrite issues a new lease",
					slog.String("template", t.Name), slog.String("lease", lease.ID))
			}
			leaseValues[ref] = lease.Credential
		}
	}
	var buf bytes.Buffer
	for _, s := range segs {
		switch {
		case s.secret != "":
			buf.Write(values[s.secret])
		case s.lease != "":
			value, err := leaseField(leaseValues[s.lease], s.field)
			if err != nil {
				return fmt.Errorf("lease %s: %w", s.lease, err)
			}
			buf.Write(value)
			secret.Wipe(value)
		default:
			buf.Write(s.literal)
		}
	}
	content := buf.Bytes()
	mode, _ := t.mode()
	own, ownErr := t.ownership()
	if ownErr != nil {
		secret.Wipe(content)
		return ownErr
	}
	writeErr := writeAtomic(t.Destination, content, mode, own)
	secret.Wipe(content)
	if writeErr != nil {
		return writeErr
	}
	st.Versions, st.WrittenAt, st.Verified, st.Removed = rendered, now, false, false
	if err := r.saveState(t, st); err != nil {
		return err
	}
	r.reportQuietly(ctx, t, "injected", rendered)
	if err := r.reload(ctx, t); err != nil {
		return fmt.Errorf("reload after writing %s: %w", t.Destination, err)
	}
	if t.Verify.URL != "" {
		if err := r.verify(ctx, t, values); err != nil {
			r.logger.Warn("application did not verify the new values", slog.String("template", t.Name), slog.String("error", err.Error()))
			return r.saveState(t, st)
		}
		st.Verified = true
		r.reportQuietly(ctx, t, "verified", rendered)
	}
	// Replacement before revocation: a replaced lease is revoked only once the
	// application took its replacement.
	r.retireLeases(ctx, t, &st)
	if err := r.saveState(t, st); err != nil {
		return err
	}
	r.logger.Info("secret template written", slog.String("template", t.Name), slog.String("destination", t.Destination))
	return nil
}

// issueLease issues a lease for ref under a key persisted first, and queues
// the lease it replaces for retirement.
func (r *Renderer) issueLease(ctx context.Context, t Template, st *templateState, ref string, ttl time.Duration) (Lease, error) {
	provider, role, _ := strings.Cut(ref, "/")
	ls := st.Leases[ref]
	if ls.IssueKey == "" {
		suffix, err := crypto.RandomBytes(12)
		if err != nil {
			return Lease{}, err
		}
		ls.IssueKey = "secret-render-lease-" + hex.EncodeToString(suffix)
		st.Leases[ref] = ls
		if err := r.saveState(t, *st); err != nil {
			return Lease{}, err
		}
	}
	lease, err := r.leases.IssueLease(ctx, provider, role, ttl, ls.IssueKey)
	if err != nil {
		return Lease{}, fmt.Errorf("issue lease %s: %w", ref, err)
	}
	if ls.ID != "" && ls.ID != lease.ID && !slices.Contains(st.Retire, ls.ID) {
		st.Retire = append(st.Retire, ls.ID)
	}
	st.Leases[ref] = leaseState{ID: lease.ID, ExpiresAt: lease.ExpiresAt, HardExpiresAt: lease.HardExpiresAt}
	return lease, nil
}

// retireLeases revokes replaced leases; one that can't be revoked now is tried
// again on the next pass.
func (r *Renderer) retireLeases(ctx context.Context, t Template, st *templateState) {
	var keep []string
	for _, id := range st.Retire {
		if err := r.leases.RevokeLease(ctx, id, id+"/retire"); err != nil {
			r.logger.Warn("a replaced lease could not be revoked yet", slog.String("template", t.Name), slog.String("lease", id))
			keep = append(keep, id)
		}
	}
	st.Retire = keep
}

// leaseField returns a copy of one JSON string field of a lease credential, or
// the whole credential when field is empty.
func leaseField(credential []byte, field string) ([]byte, error) {
	if field == "" {
		return bytes.Clone(credential), nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(credential, &fields); err != nil {
		return nil, errors.New("the credential is not a JSON object")
	}
	defer func() {
		for k, v := range fields {
			secret.Wipe(v)
			delete(fields, k)
		}
	}()
	raw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("the credential has no field %q", field)
	}
	var value secret.JSONBytes
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("field %q is not a string", field)
	}
	return value, nil
}

// stale handles a template whose values can't be fetched: within the freshness
// bound the last file keeps serving; past it, the file is removed (or kept).
func (r *Renderer) stale(ctx context.Context, t Template, st templateState, cause error) error {
	if st.FetchedAt.IsZero() || st.Removed {
		return fmt.Errorf("control plane unreachable: %w", cause)
	}
	// A lease credential is dead at its own expiry, whatever the freshness bound.
	deadline := st.FetchedAt.Add(r.cfg.Freshness)
	for _, ls := range st.Leases {
		if !ls.ExpiresAt.IsZero() && ls.ExpiresAt.Before(deadline) {
			deadline = ls.ExpiresAt
		}
	}
	if r.now().Before(deadline) {
		r.logger.Warn("serving the last values until the freshness bound", slog.String("template", t.Name),
			slog.Time("fresh_until", deadline))
		return nil
	}
	if t.OnStale == stateKeep {
		r.logger.Warn("the freshness bound passed; keeping the file as configured", slog.String("template", t.Name))
		return nil
	}
	if err := os.Remove(t.Destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The file is gone: its held lease credentials go with it.
	r.held.keep(t.Name, nil)
	st.Removed, st.Verified = true, false
	if err := r.saveState(t, st); err != nil {
		return err
	}
	r.logger.Warn("removed a file past its freshness bound", slog.String("template", t.Name), slog.String("destination", t.Destination))
	return r.reload(ctx, t)
}

func (r *Renderer) reload(ctx context.Context, t Template) error {
	switch {
	case len(t.Reload.Command) > 0:
		return runHook(ctx, t.Reload.Command)
	case t.Reload.Signal != "":
		raw, err := os.ReadFile(t.Reload.PIDFile) // #nosec G304 -- operator-configured pid file (CWE-22)
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid <= 1 {
			return errors.New("secretrender: the pid file does not name a process")
		}
		return signalProcess(pid, t.Reload.Signal)
	}
	return nil
}

// runHook runs an operator-configured reload argv directly, with no shell, a
// deadline and discarded output.
func runHook(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- operator-configured reload argv from the renderer's own configuration; running it is the feature (CWE-78)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}

func (r *Renderer) verify(ctx context.Context, t Template, values map[string][]byte) error {
	timeout := t.Verify.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	want := t.Verify.ExpectStatus
	if want == 0 {
		want = http.StatusOK
	}
	// The application is a loopback http endpoint or a public https one, the
	// same rule every operator-configured endpoint follows.
	client, err := netsec.OutboundClientForEndpoint(t.Verify.URL, 10*time.Second)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Verify.URL, nil)
		if err != nil {
			return err
		}
		if t.Verify.PasswordSecret != "" {
			req.SetBasicAuth(t.Verify.Username, secrettext.String(values[t.Verify.PasswordSecret]))
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return nil
			}
			last = fmt.Errorf("the application answered %d, want %d", resp.StatusCode, want)
		} else {
			last = errors.New("the application could not be reached")
		}
		if time.Now().After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (r *Renderer) reportQuietly(ctx context.Context, t Template, state string, versions map[string]int) {
	if r.report == nil || len(versions) == 0 {
		return
	}
	if err := r.report.Report(ctx, r.cfg.Consumer, state, versions); err != nil {
		r.logger.Warn("delivery report not sent", slog.String("template", t.Name), slog.String("state", state), slog.String("error", err.Error()))
	}
}

// writeAtomic writes content to path so a reader sees the old file or the new
// one, never a partial: a private temporary file in the same directory is
// restricted (on Windows, an explicit DACL from its mode, before any content),
// written, flushed and given its mode, then renamed over path, and the
// directory is flushed.
func writeAtomic(path string, content []byte, mode os.FileMode, own *fileOwnership) error {
	dir := filepath.Dir(path)
	suffix, err := crypto.RandomBytes(8)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".trstctl-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a fresh random name beside the configured destination (CWE-22)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if err := restrictPath(tmp, mode); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	// A238-L2: the private temporary file is given away before the rename,
	// so the destination is never seen with another owner.
	if own != nil {
		if err := f.Chown(own.uid, own.gid); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("secretrender: give %s to %d:%d: %w", path, own.uid, own.gid, err)
		}
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := replaceFile(tmp, path, mode); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the destination's own directory (CWE-22)
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ErrRefused is the control plane refusing a read (403 or 404): the caller may
// not read the secret, or it doesn't exist. ErrUnauthenticated is a 401: the
// control plane no longer accepts the caller's token.
var (
	ErrRefused         = errors.New("secretrender: the control plane refused the read")
	ErrUnauthenticated = errors.New("secretrender: the control plane did not accept the token")
)

type refusedError struct {
	status int
	name   string
}

func (e refusedError) Error() string {
	return fmt.Sprintf("the control plane answered %d for %s", e.status, e.name)
}

func (e refusedError) Is(target error) bool {
	if e.status == http.StatusUnauthorized {
		return target == ErrUnauthenticated
	}
	return target == ErrRefused
}

// HTTPClient reads secrets and sends reports to a control plane with an API
// token. The token is held as bytes and turned into a header per request.
type HTTPClient struct {
	server string
	tenant string
	token  []byte
	client *http.Client
}

// NewHTTPClient builds a control-plane client over a client the caller built
// through a reviewed path (a CA-pinned transport, or netsec's endpoint rule);
// the token is read from its file.
func NewHTTPClient(server, tenant, tokenFile string, client *http.Client) (*HTTPClient, error) {
	if client == nil {
		return nil, errors.New("secretrender: a control-plane client is required")
	}
	token, err := os.ReadFile(tokenFile) // #nosec G304 -- operator-configured token file (CWE-22)
	if err != nil {
		return nil, err
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 {
		return nil, errors.New("secretrender: the token file is empty")
	}
	return &HTTPClient{server: strings.TrimRight(server, "/"), tenant: tenant, token: token, client: client}, nil
}

// NewSessionHTTPClient builds a control-plane client over a session token the
// caller obtained (a machine login); the client keeps token and Wipe clears it.
func NewSessionHTTPClient(server, tenant string, token []byte, client *http.Client) (*HTTPClient, error) {
	if client == nil || len(token) == 0 {
		return nil, errors.New("secretrender: a control-plane client and a session token are required")
	}
	return &HTTPClient{server: strings.TrimRight(server, "/"), tenant: tenant, token: token, client: client}, nil
}

// Wipe clears the client's token; the client can't be used afterwards.
func (c *HTTPClient) Wipe() {
	secret.Wipe(c.token)
	c.token = nil
}

func (c *HTTPClient) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+secrettext.String(c.token))
	if c.tenant != "" {
		req.Header.Set("X-Tenant-ID", c.tenant)
	}
	return c.client.Do(req)
}

// EndSession ends the machine session this client presents (A238-L7), so its
// token stops working now rather than at its expiry. A session that has
// already ended (expired, revoked, or ended by an earlier try whose answer was
// lost) is refused 401, which counts as ended.
func (c *HTTPClient) EndSession(ctx context.Context, idempotencyKey string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+"/api/v1/secrets/sessions/self/revoke", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Idempotency-Key", idempotencyKey)
	resp, err := c.do(req)
	if err != nil {
		return errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
		return nil
	}
	return fmt.Errorf("the control plane answered %d", resp.StatusCode)
}

// Fetch reads one secret, with references resolved.
func (c *HTTPClient) Fetch(ctx context.Context, name string) ([]byte, int, error) {
	parts := strings.Split(name, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+"/api/v1/secrets/store/"+strings.Join(parts, "/")+"?resolve=true", nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, 0, errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil, 0, refusedError{resp.StatusCode, name}
	default:
		return nil, 0, fmt.Errorf("the control plane answered %d for %s", resp.StatusCode, name)
	}
	var body struct {
		Value   secret.JSONBytes `json:"value"`
		Version int              `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || body.Version < 1 {
		secret.Wipe(body.Value)
		return nil, 0, errors.New("the control plane's answer could not be read")
	}
	return []byte(body.Value), body.Version, nil
}

// Report sends a delivery report; its idempotency key is the report itself.
func (c *HTTPClient) Report(ctx context.Context, consumer, state string, versions map[string]int) error {
	type item struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	items := make([]item, 0, len(versions))
	for _, name := range slices.Sorted(maps.Keys(versions)) {
		items = append(items, item{name, versions[name]})
	}
	raw, err := json.Marshal(map[string]any{"consumer": consumer, "state": state, "secrets": items})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+"/api/v1/secrets/deliveries", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "secret-delivery-"+crypto.SHA256Hex(raw)[:32])
	resp, err := c.do(req)
	if err != nil {
		return errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		// A238-L1: a session client signs in again on this.
		return refusedError{resp.StatusCode, "the delivery report"}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane answered %d", resp.StatusCode)
	}
	return nil
}

// IssueLease issues a dynamic lease; the credential is in this answer only.
func (c *HTTPClient) IssueLease(ctx context.Context, provider, role string, ttl time.Duration, key string) (Lease, error) {
	raw, err := json.Marshal(map[string]any{"provider": provider, "role": role, "ttl_seconds": int(ttl / time.Second)})
	if err != nil {
		return Lease{}, err
	}
	var body struct {
		ID            string           `json:"id"`
		Credential    secret.JSONBytes `json:"credential"`
		ExpiresAt     time.Time        `json:"expires_at"`
		HardExpiresAt *time.Time       `json:"hard_expires_at"`
	}
	if err := c.post(ctx, "/api/v1/secrets/leases", key, raw, &body); err != nil {
		return Lease{}, err
	}
	if body.ID == "" || len(body.Credential) == 0 {
		secret.Wipe(body.Credential)
		return Lease{}, errors.New("the control plane issued no credential yet")
	}
	lease := Lease{ID: body.ID, Credential: []byte(body.Credential), ExpiresAt: body.ExpiresAt}
	if body.HardExpiresAt != nil {
		lease.HardExpiresAt = *body.HardExpiresAt
	}
	return lease, nil
}

// RenewLease extends a lease and returns its new expiry.
func (c *HTTPClient) RenewLease(ctx context.Context, id string, extend time.Duration, key string) (time.Time, error) {
	raw, err := json.Marshal(map[string]any{"extend_seconds": int(extend / time.Second)})
	if err != nil {
		return time.Time{}, err
	}
	var body struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.post(ctx, "/api/v1/secrets/leases/"+url.PathEscape(id)+"/renew", key, raw, &body); err != nil {
		return time.Time{}, err
	}
	return body.ExpiresAt, nil
}

// RevokeLease revokes a lease.
func (c *HTTPClient) RevokeLease(ctx context.Context, id, key string) error {
	return c.post(ctx, "/api/v1/secrets/leases/"+url.PathEscape(id)+"/revoke", key, []byte("{}"), nil)
}

func (c *HTTPClient) post(ctx context.Context, path, key string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	resp, err := c.do(req)
	if err != nil {
		return errors.New("the control plane could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return refusedError{resp.StatusCode, path}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the control plane answered %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return errors.New("the control plane's answer could not be read")
	}
	return nil
}
