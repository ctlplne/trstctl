// SPDX-License-Identifier: BUSL-1.1

// Package postfix deploys renewed TLS credentials to a mail server that serves
// both Postfix SMTP and Dovecot IMAP. It writes the same certificate/key pair to
// each service's configured files, validates both daemons, then reloads them.
//
// Delivery is outbox-driven through connector.Registry (AN-6). PEM material is
// opaque []byte (AN-8), idempotency is SHA-256 through internal/crypto (AN-3),
// and all filesystem/exec operations are capability-gated by the connector SDK.
package postfix

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
)

const metricName = "trstctl_postfix_deployments_total"

// ServiceConfig is the file and command configuration for one mail daemon.
type ServiceConfig struct {
	CertPath        string
	KeyPath         string
	ValidateCommand []string
	ReloadCommand   []string
}

// Config contains the two services a mail deployment must keep in lockstep.
type Config struct {
	Postfix ServiceConfig
	Dovecot ServiceConfig
}

// Connector deploys one credential to Postfix and Dovecot.
type Connector struct {
	cfg     Config
	metrics *observ.CounterVec
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithMetrics records per-target deployment counters in registry.
func WithMetrics(reg *observ.Registry) Option {
	return func(c *Connector) {
		if reg != nil {
			c.metrics = reg.CounterVec(metricName, "Postfix/Dovecot connector deployments by target and result.", []string{"target", "result"})
		}
	}
}

// New returns a connector that updates both Postfix and Dovecot TLS files.
func New(cfg Config, opts ...Option) *Connector {
	c := &Connector{cfg: withDefaults(cfg)}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "postfix" }

// Capabilities declares least privilege: read/write only the configured mail
// certificate directories and run local validate/reload commands. No network is
// needed.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSRead, pluginhost.CapFSWrite, connector.CapExec)
	for _, svc := range c.services() {
		g = withFileGrant(g, svc.cfg.CertPath)
		g = withFileGrant(g, svc.cfg.KeyPath)
	}
	return g
}

// Deploy writes both daemons' certificate/key files, validates both configs, and
// reloads both services. Any failure after the old state is read restores every
// previously existing file.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := c.validate(); err != nil {
		c.observe(dep.Target, "invalid_config")
		return err
	}
	files := c.files(dep)
	old, err := readStates(sb, files)
	if err != nil {
		c.observe(dep.Target, "error")
		return err
	}
	defer wipeStates(old)
	if allSame(old, files, dep) {
		c.observe(dep.Target, "noop")
		return nil
	}
	for _, f := range files {
		if err := sb.WriteFile(f.path, f.data); err != nil {
			return c.failWithRollback(sb, old, dep.Target, "write "+f.label, err)
		}
	}
	for _, svc := range c.services() {
		if len(svc.cfg.ValidateCommand) == 0 {
			continue
		}
		cmd := svc.cfg.ValidateCommand
		if err := sb.Exec(cmd[0], cmd[1:]...); err != nil {
			return c.failWithRollback(sb, old, dep.Target, svc.name+" validate", err)
		}
	}
	for _, svc := range c.services() {
		if len(svc.cfg.ReloadCommand) == 0 {
			continue
		}
		cmd := svc.cfg.ReloadCommand
		if err := sb.Exec(cmd[0], cmd[1:]...); err != nil {
			return c.failWithRollback(sb, old, dep.Target, svc.name+" reload", err)
		}
	}
	c.observe(dep.Target, "deployed")
	return nil
}

func withDefaults(cfg Config) Config {
	cfg.Postfix = defaultService(cfg.Postfix, ServiceConfig{
		CertPath:        "/etc/postfix/certs/server.pem",
		KeyPath:         "/etc/postfix/certs/server.key",
		ValidateCommand: []string{"postfix", "check"},
		ReloadCommand:   []string{"postfix", "reload"},
	})
	cfg.Dovecot = defaultService(cfg.Dovecot, ServiceConfig{
		CertPath:        "/etc/dovecot/certs/server.pem",
		KeyPath:         "/etc/dovecot/certs/server.key",
		ValidateCommand: []string{"doveconf", "-n"},
		ReloadCommand:   []string{"doveadm", "reload"},
	})
	return cfg
}

func defaultService(got, def ServiceConfig) ServiceConfig {
	if got.CertPath == "" {
		got.CertPath = def.CertPath
	}
	if got.KeyPath == "" {
		got.KeyPath = def.KeyPath
	}
	if got.ValidateCommand == nil {
		got.ValidateCommand = append([]string(nil), def.ValidateCommand...)
	}
	if got.ReloadCommand == nil {
		got.ReloadCommand = append([]string(nil), def.ReloadCommand...)
	}
	return got
}

func withFileGrant(g pluginhost.Grant, file string) pluginhost.Grant {
	dir := path.Dir(file)
	return g.WithPathPrefix(pluginhost.CapFSRead, dir).WithPathPrefix(pluginhost.CapFSWrite, dir)
}

type namedService struct {
	name string
	cfg  ServiceConfig
}

func (c *Connector) services() []namedService {
	return []namedService{
		{name: "postfix", cfg: c.cfg.Postfix},
		{name: "dovecot", cfg: c.cfg.Dovecot},
	}
}

func (c *Connector) validate() error {
	for _, svc := range c.services() {
		if svc.cfg.CertPath == "" {
			return fmt.Errorf("postfix: %s cert path is required", svc.name)
		}
		if svc.cfg.KeyPath == "" {
			return fmt.Errorf("postfix: %s key path is required", svc.name)
		}
		if err := ValidateCommand(svc.cfg.ValidateCommand); err != nil {
			return fmt.Errorf("postfix: invalid %s validate command: %w", svc.name, err)
		}
		if err := ValidateCommand(svc.cfg.ReloadCommand); err != nil {
			return fmt.Errorf("postfix: invalid %s reload command: %w", svc.name, err)
		}
	}
	return nil
}

type desiredFile struct {
	label string
	path  string
	data  []byte
	cert  bool
}

func (c *Connector) files(dep connector.Deployment) []desiredFile {
	out := make([]desiredFile, 0, 4)
	for _, svc := range c.services() {
		out = append(out,
			desiredFile{label: svc.name + " certificate", path: svc.cfg.CertPath, data: dep.CertPEM, cert: true},
			desiredFile{label: svc.name + " key", path: svc.cfg.KeyPath, data: dep.KeyPEM},
		)
	}
	return out
}

type fileState struct {
	path string
	data []byte
	had  bool
}

func readStates(sb connector.Sandbox, files []desiredFile) (map[string]fileState, error) {
	out := make(map[string]fileState, len(files))
	for _, f := range files {
		b, err := sb.ReadFile(f.path)
		if err == nil {
			out[f.path] = fileState{path: f.path, data: b, had: true}
			continue
		}
		if os.IsNotExist(err) {
			out[f.path] = fileState{path: f.path}
			continue
		}
		wipeStates(out)
		return nil, fmt.Errorf("postfix: read current %s: %w", f.label, err)
	}
	return out, nil
}

func wipeStates(states map[string]fileState) {
	for key, state := range states {
		secret.Wipe(state.data)
		state.data = nil
		states[key] = state
	}
}

func allSame(old map[string]fileState, files []desiredFile, dep connector.Deployment) bool {
	for _, f := range files {
		st := old[f.path]
		if !st.had {
			return false
		}
		if f.cert {
			if connector.CertificateFingerprint(st.data) != dep.Fingerprint {
				return false
			}
			continue
		}
		if !bytes.Equal(st.data, f.data) {
			return false
		}
	}
	return true
}

func (c *Connector) failWithRollback(sb connector.Sandbox, old map[string]fileState, target, stage string, err error) error {
	rollbackErr := rollback(sb, old)
	c.observe(target, "rollback")
	if rollbackErr != nil {
		return fmt.Errorf("postfix: %s failed and rollback failed: %w rollback=%v", stage, err, rollbackErr)
	}
	return fmt.Errorf("postfix: %s failed; rollback complete: %w", stage, err)
}

func rollback(sb connector.Sandbox, old map[string]fileState) error {
	for _, st := range old {
		if !st.had {
			continue
		}
		if err := sb.WriteFile(st.path, st.data); err != nil {
			return fmt.Errorf("restore %s: %w", st.path, err)
		}
	}
	return nil
}

func (c *Connector) observe(target, result string) {
	if c.metrics != nil {
		c.metrics.WithLabelValues(target, result).Inc()
	}
}

// ValidateCommand rejects shell-oriented command strings. The connector invokes
// argv directly, and this keeps shell pipelines out of mail-server config.
func ValidateCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("command is required")
	}
	if err := validateToken("command", cmd[0]); err != nil {
		return err
	}
	if shellName(cmd[0]) {
		return fmt.Errorf("command %q is a shell interpreter; configure the service binary directly", cmd[0])
	}
	for i, arg := range cmd[1:] {
		if err := validateToken(fmt.Sprintf("arg[%d]", i), arg); err != nil {
			return err
		}
	}
	return nil
}

func validateToken(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if strings.ContainsAny(value, "\x00\r\n;&|`$<>{}[]*?") {
		return fmt.Errorf("%s %q contains shell metacharacters", label, value)
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%s %q contains whitespace; configure argv tokens explicitly", label, value)
		}
	}
	return nil
}

func shellName(command string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}
