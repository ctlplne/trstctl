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
	Server    string        `yaml:"server" json:"server"`
	CAFile    string        `yaml:"ca_file" json:"ca_file"`
	TokenFile string        `yaml:"token_file" json:"token_file"`
	Tenant    string        `yaml:"tenant" json:"tenant"`
	Consumer  string        `yaml:"consumer" json:"consumer"`
	Interval  time.Duration `yaml:"interval" json:"interval"`
	Freshness time.Duration `yaml:"freshness" json:"freshness"`
	StateDir  string        `yaml:"state_dir" json:"state_dir"`
	Templates []Template    `yaml:"templates" json:"templates"`
}

// Template is one rendered file.
type Template struct {
	Name        string `yaml:"name" json:"name"`
	Destination string `yaml:"destination" json:"destination"`
	// Mode is the file's octal permission bits; 0400 when empty.
	Mode   string `yaml:"mode" json:"mode"`
	Text   string `yaml:"template" json:"template"`
	Reload Hook   `yaml:"reload" json:"reload"`
	Verify Verify `yaml:"verify" json:"verify"`
	// OnStale is what happens when the freshness bound passes without reaching
	// the control plane: remove (the default) or keep.
	OnStale string `yaml:"on_stale" json:"on_stale"`
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

const (
	defaultInterval  = 30 * time.Second
	defaultFreshness = time.Hour
	stateRemove      = "remove"
	stateKeep        = "keep"
)

var placeholder = regexp.MustCompile(`^\{\{\s*secret\s+"([^"]{1,512})"\s*\}\}`)

type segment struct {
	literal []byte
	secret  string
}

// parseTemplate splits text into literal bytes and secret placeholders. Only
// {{ secret "name" }} is supported, so a template can't run code.
func parseTemplate(text string) ([]segment, []string, error) {
	var segs []segment
	var names []string
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
		m := placeholder.FindStringSubmatch(rest[idx:])
		if m == nil {
			return nil, nil, errors.New(`secretrender: only {{ secret "name" }} placeholders are supported`)
		}
		segs = append(segs, segment{secret: m[1]})
		if !slices.Contains(names, m[1]) {
			names = append(names, m[1])
		}
		rest = rest[idx+len(m[0]):]
	}
	return segs, names, nil
}

// Validate checks a configuration before anything runs.
func (c *Config) Validate() error {
	switch {
	case c.Server == "" || c.TokenFile == "" || c.Consumer == "" || c.StateDir == "":
		return errors.New("secretrender: server, token_file, consumer and state_dir are required")
	case len(c.Templates) == 0:
		return errors.New("secretrender: at least one template is required")
	}
	seen := map[string]bool{}
	for _, t := range c.Templates {
		if t.Name == "" || seen[t.Name] || !filepath.IsAbs(t.Destination) {
			return fmt.Errorf("secretrender: template %q needs a unique name and an absolute destination", t.Name)
		}
		seen[t.Name] = true
		if _, _, err := parseTemplate(t.Text); err != nil {
			return fmt.Errorf("template %s: %w", t.Name, err)
		}
		if _, err := t.mode(); err != nil {
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
	Versions  map[string]int `json:"versions"`
	FetchedAt time.Time      `json:"fetched_at"`
	WrittenAt time.Time      `json:"written_at"`
	Verified  bool           `json:"verified"`
	Removed   bool           `json:"removed,omitempty"`
}

// Renderer keeps a configuration's files current.
type Renderer struct {
	cfg    Config
	fetch  Fetcher
	report Reporter
	logger *slog.Logger
	now    func() time.Time
}

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

// Run reconciles every template now and then on each interval until ctx ends.
func (r *Renderer) Run(ctx context.Context) error {
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
	return writeAtomic(r.statePath(t), raw, 0o600)
}

func (r *Renderer) reconcile(ctx context.Context, t Template) error {
	segs, names, err := parseTemplate(t.Text)
	if err != nil {
		return err
	}
	st := r.loadState(t)
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
	if maps.Equal(rendered, st.Versions) && statErr == nil && !st.Removed {
		if !st.Verified && t.Verify.URL != "" && r.verify(ctx, t, values) == nil {
			st.Verified = true
			r.reportQuietly(ctx, t, "verified", rendered)
		}
		return r.saveState(t, st)
	}
	var buf bytes.Buffer
	for _, s := range segs {
		if s.secret != "" {
			buf.Write(values[s.secret])
			continue
		}
		buf.Write(s.literal)
	}
	content := buf.Bytes()
	mode, _ := t.mode()
	writeErr := writeAtomic(t.Destination, content, mode)
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
			return nil
		}
		st.Verified = true
		if err := r.saveState(t, st); err != nil {
			return err
		}
		r.reportQuietly(ctx, t, "verified", rendered)
	}
	r.logger.Info("secret template written", slog.String("template", t.Name), slog.String("destination", t.Destination))
	return nil
}

// stale handles a template whose values can't be fetched: within the freshness
// bound the last file keeps serving; past it, the file is removed (or kept).
func (r *Renderer) stale(ctx context.Context, t Template, st templateState, cause error) error {
	if st.FetchedAt.IsZero() || st.Removed {
		return fmt.Errorf("control plane unreachable: %w", cause)
	}
	deadline := st.FetchedAt.Add(r.cfg.Freshness)
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
// written, flushed and given its mode, then renamed over path, and the
// directory is flushed.
func writeAtomic(path string, content []byte, mode os.FileMode) error {
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
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the destination's own directory (CWE-22)
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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

func (c *HTTPClient) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+secrettext.String(c.token))
	if c.tenant != "" {
		req.Header.Set("X-Tenant-ID", c.tenant)
	}
	return c.client.Do(req)
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
	if resp.StatusCode != http.StatusOK {
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
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the control plane answered %d", resp.StatusCode)
	}
	return nil
}
