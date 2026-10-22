// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
)

// NTLM browser login (A80) relays the NTLMSSP handshake to a domain-joined
// helper speaking the squid-2.5-ntlmssp line protocol (Samba's ntlm_auth):
// "YR <type1>" answers "TT <type2>", "KK <type3>" answers "AF <account>" or
// "NA <reason>" / "BH <reason>". trstctl never sees a password hash and never
// validates an NTLM response itself. One helper session serves one handshake,
// and the handshake is bound to one client connection the way NTLM over HTTP
// requires.

const (
	ntlmMaxTokenBytes    = 16 << 10
	ntlmMaxLineBytes     = 64 << 10
	ntlmPendingTTL       = 30 * time.Second
	ntlmMaxPendingPerSrv = 1024
	ntlmSignature        = "NTLMSSP\x00"
)

// NTLMHelperSession is one handshake with the helper.
type NTLMHelperSession interface {
	Challenge(type1 string) (type2 string, err error)
	Authenticate(type3 string) (account string, err error)
	Close() error
}

// NTLMHelperFactory opens a helper session for one handshake.
type NTLMHelperFactory func(ctx context.Context) (NTLMHelperSession, error)

// lineHelper drives the squid helper protocol over any line-oriented pipe.
type lineHelper struct {
	r     *bufio.Reader
	w     io.Writer
	close func() error
}

func (h *lineHelper) exchange(verb, payload string) (string, string, error) {
	if _, err := io.WriteString(h.w, verb+" "+payload+"\n"); err != nil {
		return "", "", fmt.Errorf("ntlm helper: write %s: %w", verb, err)
	}
	line, err := h.r.ReadString('\n')
	if err != nil && line == "" {
		return "", "", fmt.Errorf("ntlm helper: no answer to %s: %w", verb, err)
	}
	line = strings.TrimRight(line, "\r\n")
	code, rest, _ := strings.Cut(line, " ")
	return code, rest, nil
}

func (h *lineHelper) Challenge(type1 string) (string, error) {
	code, rest, err := h.exchange("YR", type1)
	if err != nil {
		return "", err
	}
	if code != "TT" || rest == "" {
		return "", fmt.Errorf("ntlm helper: expected a TT challenge, got %q", code)
	}
	return rest, nil
}

func (h *lineHelper) Authenticate(type3 string) (string, error) {
	code, rest, err := h.exchange("KK", type3)
	if err != nil {
		return "", err
	}
	switch code {
	case "AF":
		if strings.TrimSpace(rest) == "" {
			return "", errors.New("ntlm helper: AF without an account")
		}
		return strings.TrimSpace(rest), nil
	case "NA":
		return "", fmt.Errorf("ntlm helper: authentication refused: %s", strings.TrimSpace(rest))
	case "BH":
		return "", fmt.Errorf("ntlm helper: helper failure: %s", strings.TrimSpace(rest))
	}
	return "", fmt.Errorf("ntlm helper: unexpected answer %q to KK", code)
}

func (h *lineHelper) Close() error {
	if h.close != nil {
		return h.close()
	}
	return nil
}

// NTLMCommandHelper runs the helper as a local process per handshake.
func NTLMCommandHelper(command string, args []string, timeout time.Duration) NTLMHelperFactory {
	return func(ctx context.Context) (NTLMHelperSession, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 -- operator-pinned absolute helper path from deployment configuration, validated at startup (CWE-78)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			return nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			cancel()
			return nil, fmt.Errorf("ntlm helper: start %s: %w", command, err)
		}
		return &lineHelper{r: bufio.NewReaderSize(io.LimitReader(stdout, ntlmMaxLineBytes), 4096), w: stdin, close: func() error {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			cancel()
			return nil
		}}, nil
	}
}

// NTLMSocketHelper reaches a helper exposed over tcp://host:port or
// unix:///path, one connection per handshake.
func NTLMSocketHelper(address string, timeout time.Duration) (NTLMHelperFactory, error) {
	network, target := "", ""
	switch {
	case strings.HasPrefix(address, "tcp://"):
		network, target = "tcp", strings.TrimPrefix(address, "tcp://")
	case strings.HasPrefix(address, "unix://"):
		network, target = "unix", strings.TrimPrefix(address, "unix://")
	default:
		return nil, fmt.Errorf("ntlm helper: address %q must be tcp://host:port or unix:///path", address)
	}
	if target == "" {
		return nil, errors.New("ntlm helper: address names no target")
	}
	return func(ctx context.Context) (NTLMHelperSession, error) {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, network, target)
		if err != nil {
			return nil, fmt.Errorf("ntlm helper: dial %s: %w", address, err)
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		return &lineHelper{r: bufio.NewReaderSize(io.LimitReader(conn, ntlmMaxLineBytes), 4096), w: conn, close: conn.Close}, nil
	}, nil
}

// NTLMVerifier serves the NTLM-over-HTTP handshake for one helper.
type NTLMVerifier struct {
	Helper NTLMHelperFactory
	// Domain, when set, admits only accounts the helper reports in it.
	Domain string

	mu      sync.Mutex
	pending map[string]*ntlmPending
}

type ntlmPending struct {
	session NTLMHelperSession
	expires time.Time
}

// ntlmMessageType reads the NTLMSSP message type (1 negotiate, 2 challenge, 3
// authenticate) from a decoded token.
func ntlmMessageType(raw []byte) (uint32, bool) {
	if len(raw) < 12 || string(raw[:8]) != ntlmSignature {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw[8:12]), true
}

func (v *NTLMVerifier) take(key string) *ntlmPending {
	v.mu.Lock()
	defer v.mu.Unlock()
	p := v.pending[key]
	delete(v.pending, key)
	return p
}

func (v *NTLMVerifier) keep(key string, session NTLMHelperSession) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.pending == nil {
		v.pending = map[string]*ntlmPending{}
	}
	now := time.Now()
	for k, p := range v.pending {
		if !p.expires.After(now) {
			_ = p.session.Close()
			delete(v.pending, k)
		}
	}
	if old := v.pending[key]; old != nil {
		_ = old.session.Close()
	}
	if len(v.pending) >= ntlmMaxPendingPerSrv {
		_ = session.Close()
		return
	}
	v.pending[key] = &ntlmPending{session: session, expires: now.Add(ntlmPendingTTL)}
}

func ntlmChallenge(w http.ResponseWriter, token string) {
	if token == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
	} else {
		w.Header().Set("WWW-Authenticate", "NTLM "+token)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
}

// Login wraps next in the NTLM handshake: 401 NTLM, then the helper's
// challenge, then the helper's verdict on the authenticate message.
func (v *NTLMVerifier) Login(next func(http.ResponseWriter, *http.Request, auth.Claims)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "NTLM ") {
			ntlmChallenge(w, "")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, "NTLM "))
		raw, err := base64.StdEncoding.DecodeString(token)
		if err != nil || len(raw) > ntlmMaxTokenBytes {
			ntlmChallenge(w, "")
			return
		}
		kind, ok := ntlmMessageType(raw)
		if !ok {
			ntlmChallenge(w, "")
			return
		}
		key := r.RemoteAddr
		switch kind {
		case 1:
			if old := v.take(key); old != nil {
				_ = old.session.Close()
			}
			session, err := v.Helper(r.Context())
			if err != nil {
				http.Error(w, "NTLM helper is unavailable", http.StatusBadGateway)
				return
			}
			type2, err := session.Challenge(token)
			if err != nil {
				_ = session.Close()
				http.Error(w, "NTLM helper did not issue a challenge", http.StatusBadGateway)
				return
			}
			v.keep(key, session)
			ntlmChallenge(w, type2)
		case 3:
			p := v.take(key)
			if p == nil || !p.expires.After(time.Now()) {
				if p != nil {
					_ = p.session.Close()
				}
				ntlmChallenge(w, "")
				return
			}
			account, err := p.session.Authenticate(token)
			_ = p.session.Close()
			if err != nil {
				ntlmChallenge(w, "")
				return
			}
			claims, ok := ntlmClaims(account, v.Domain)
			if !ok {
				ntlmChallenge(w, "")
				return
			}
			next(w, r, claims)
		default:
			ntlmChallenge(w, "")
		}
	})
}

// ntlmClaims normalizes the helper's account (DOMAIN\\user or user@domain)
// into user@DOMAIN and refuses an account outside the pinned domain.
func ntlmClaims(account, pinnedDomain string) (auth.Claims, bool) {
	account = strings.TrimSpace(account)
	var user, domain string
	switch {
	case strings.Contains(account, `\`):
		domain, user, _ = strings.Cut(account, `\`)
	case strings.Contains(account, "@"):
		user, domain, _ = strings.Cut(account, "@")
	default:
		user = account
	}
	user, domain = strings.TrimSpace(user), strings.ToUpper(strings.TrimSpace(domain))
	if user == "" {
		return auth.Claims{}, false
	}
	if pinnedDomain != "" && !strings.EqualFold(domain, pinnedDomain) {
		return auth.Claims{}, false
	}
	subject := user
	if domain != "" {
		subject = user + "@" + domain
	}
	return auth.Claims{Subject: subject, Issuer: domain, IssuedAt: time.Now().Unix()}, true
}

func buildNTLMAuthConfig(n config.NTLM, secure bool, newSessionIssuer func([]byte, time.Duration) *auth.SessionIssuer) (*api.AuthConfig, error) {
	if !n.Enabled {
		return nil, nil
	}
	if err := n.ValidateEnabled(); err != nil {
		return nil, fmt.Errorf("server: NTLM login enabled but misconfigured (fail closed): %w", err)
	}
	timeout, err := n.HelperTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ntlm.helper_timeout: %w", err)
	}
	var helper NTLMHelperFactory
	if command := strings.TrimSpace(n.HelperCommand); command != "" {
		args := n.HelperArgs
		if len(args) == 0 {
			args = []string{"--helper-protocol=squid-2.5-ntlmssp"}
		}
		helper = NTLMCommandHelper(command, args, timeout)
	} else {
		helper, err = NTLMSocketHelper(strings.TrimSpace(n.HelperAddress), timeout)
		if err != nil {
			return nil, fmt.Errorf("server: auth.ntlm: %w", err)
		}
	}
	secret, err := loadOrCreateNamedSessionSecret("auth.ntlm.session_secret_file", n.SessionSecretFile)
	if err != nil {
		return nil, err
	}
	ttl, err := n.SessionTTLDuration()
	if err != nil {
		return nil, fmt.Errorf("server: auth.ntlm.session_ttl: %w", err)
	}
	mapper := tenantMapperFromNTLMConfig(n)
	verifier := &NTLMVerifier{Helper: helper, Domain: strings.TrimSpace(n.Domain)}
	return &api.AuthConfig{
		NTLMEnabled:        true,
		NTLMLogin:          verifier.Login,
		ResolveNTLMTenant:  mapper.ResolveTenant,
		TenantMappings:     ntlmMappingsForAPI(n),
		AllowDefaultTenant: n.AllowDefaultTenant,
		DefaultTenant:      n.DefaultTenant,
		DefaultRoles:       n.DefaultRoles,
		Sessions:           newSessionIssuer(secret, ttl),
		LoginRedirect:      n.LoginRedirect,
		Secure:             secure,
	}, nil
}

func ntlmMappingsForAPI(n config.NTLM) []api.AuthTenantMapping {
	out := make([]api.AuthTenantMapping, 0, len(n.TenantMappings))
	for _, m := range n.TenantMappings {
		out = append(out, api.AuthTenantMapping{Subject: m.Subject, Claim: m.Claim, Group: m.Group, TenantID: m.TenantID, Roles: append([]string(nil), m.Roles...)})
	}
	return out
}

func tenantMapperFromNTLMConfig(n config.NTLM) auth.TenantMapper {
	mappings := make([]auth.TenantMapping, 0, len(n.TenantMappings))
	for _, m := range n.TenantMappings {
		mappings = append(mappings, auth.TenantMapping{Subject: m.Subject, Claim: m.Claim, Group: m.Group, TenantID: m.TenantID, Roles: m.Roles})
	}
	return auth.TenantMapper{Mappings: mappings, DefaultTenant: n.DefaultTenant, DefaultRoles: n.DefaultRoles, AllowDefault: n.AllowDefaultTenant}
}
