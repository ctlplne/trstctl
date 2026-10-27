// SPDX-License-Identifier: BUSL-1.1

// Command a2aagent is the reference agent-to-agent pair, built on the official
// A2A Go SDK (A2A protocol 1.0):
//
//	a2aagent serve --config agent.json
//	a2aagent call --card https://127.0.0.1:9443 --expect-agent agent-b \
//	    --tls-cert a.pem --tls-key a-key.pem --agent-ca ca.pem \
//	    --credential a.der --credential-id <id> --skill research --text "..."
//
// One agent serves skills over A2A; another calls it. Both use their trstctl
// agent identities, as the A2A specification's own mechanisms carry them:
//
//   - the serving agent's Agent Card declares two security requirements, mutual
//     TLS with the caller's trstctl agent certificate and the caller's delegated
//     credential in a header, and is signed (JWS over the JCS-canonical card) with
//     the serving agent's certificate key;
//   - the calling agent accepts the card only when its signature verifies with the
//     key of the TLS peer that served it, whose certificate chains to the trusted
//     agent CA and names the agent it meant to reach;
//   - every request is authenticated by its mutual-TLS identity and authorized by
//     the delegation gate: the skill's tool and operation must be within the
//     caller's delegated scope, the credential must be delegated to the connected
//     agent, and trstctl must report it active. A refusal is an A2A authorization
//     error before any task exists.
package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2acrypto"
	"github.com/a2aproject/a2a-go/v2/a2asrv"

	"trstctl.com/trstctl/test/interop/agentframeworks/present"
	"trstctl.com/trstctl/test/interop/agentframeworks/relying"
)

// verifiedAgentHeader carries the agent ID the connection's verified certificate
// names; any client-sent value is dropped first.
const verifiedAgentHeader = "X-Relying-Verified-Agent"

const (
	identityScheme   a2a.SecuritySchemeName = "trstctl-agent-identity"
	delegationScheme a2a.SecuritySchemeName = "trstctl-delegation"
)

type serveConfig struct {
	Listen           string            `json:"listen"`
	PublicURL        string            `json:"public_url"`
	AgentID          string            `json:"agent_id"`
	TLSCertFile      string            `json:"tls_cert_file"`
	TLSKeyFile       string            `json:"tls_key_file"`
	AgentCAFile      string            `json:"agent_ca_file"`
	AgentIDPrefix    string            `json:"agent_id_prefix"`
	TenantID         string            `json:"tenant_id"`
	PinsFile         string            `json:"pins_file"`
	TrstctlURL       string            `json:"trstctl_url"`
	TrstctlCAFile    string            `json:"trstctl_ca_file"`
	TrstctlTokenFile string            `json:"trstctl_token_file"`
	Policy           relying.Policy    `json:"policy"`
	Skills           map[string]string `json:"skills"` // skill ID → the tool it uses
	StatusTTLSeconds int               `json:"status_ttl_seconds"`
	AuditFile        string            `json:"audit_file"`
}

type pins struct {
	TenantID       string   `json:"tenant_id"`
	IssuingCADER   []byte   `json:"issuing_ca_der"`
	RootAnchorDERs [][]byte `json:"root_anchor_ders"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: a2aagent serve --config FILE, or a2aagent call [flags]"))
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		path := fs.String("config", "", "configuration file")
		_ = fs.Parse(os.Args[2:])
		if err := serve(*path); err != nil {
			fail(err)
		}
	case "call":
		if err := call(os.Args[2:]); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func serve(path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- the operator names the configuration file (CWE-22)
	if err != nil {
		return err
	}
	var cfg serveConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	var pinned pins
	if raw, err = os.ReadFile(cfg.PinsFile); err != nil { // #nosec G304 G703 -- operator-named pins file (CWE-22)
		return err
	}
	if err := json.Unmarshal(raw, &pinned); err != nil {
		return err
	}
	token, err := os.ReadFile(cfg.TrstctlTokenFile) // #nosec G304 G703 -- operator-named token file (CWE-22)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(cfg.TrstctlCAFile) // #nosec G304 G703 -- operator-named CA file (CWE-22)
	if err != nil {
		return err
	}
	client, err := relying.NewClient(cfg.TrstctlURL, string(token), caPEM)
	if err != nil {
		return err
	}
	audit, err := os.OpenFile(cfg.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 G703 -- operator-named audit log (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = audit.Close() }()
	gate, err := relying.NewGate(relying.Config{
		TenantID: cfg.TenantID, IssuingCADER: pinned.IssuingCADER, RootAnchorDERs: pinned.RootAnchorDERs,
		Policy: cfg.Policy, Trstctl: client, StatusTTL: time.Duration(cfg.StatusTTLSeconds) * time.Second, Audit: audit,
	})
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	card, err := signedCard(cfg, cert)
	if err != nil {
		return err
	}
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			yield(a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("research result for "+messageText(ec.Message))), nil)
		}
	})
	handler := a2asrv.NewHandler(executor, a2asrv.WithCallInterceptors(&delegationInterceptor{gate: gate, skills: cfg.Skills}))
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("/a2a", a2asrv.NewJSONRPCHandler(handler))

	agentCAs, err := os.ReadFile(cfg.AgentCAFile) // #nosec G304 G703 -- operator-named CA bundle (CWE-22)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(agentCAs) {
		return errors.New("the agent CA file holds no certificate")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: withAgentIdentity(cfg.AgentIDPrefix, mux),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("listening %s\n", cfg.PublicURL)
	if err := server.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// signedCard describes the agent's skills and the two security requirements every
// request must meet, and signs the card with the agent's certificate key.
func signedCard(cfg serveConfig, cert tls.Certificate) (*a2a.AgentCard, error) {
	var skills []a2a.AgentSkill
	for id := range cfg.Skills {
		skills = append(skills, a2a.AgentSkill{ID: id, Name: id, Description: "uses tool " + cfg.Skills[id], Tags: []string{cfg.Skills[id]}})
	}
	card := &a2a.AgentCard{
		Name:                cfg.AgentID,
		Description:         "trstctl reference agent; callers present a trstctl agent identity and a delegated credential",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(strings.TrimSuffix(cfg.PublicURL, "/")+"/a2a", a2a.TransportProtocolJSONRPC)},
		DefaultInputModes:   []string{"text/plain"},
		DefaultOutputModes:  []string{"text/plain"},
		Skills:              skills,
		SecuritySchemes: a2a.NamedSecuritySchemes{
			identityScheme: a2a.MutualTLSSecurityScheme{Description: "the caller's trstctl agent certificate"},
			delegationScheme: a2a.APIKeySecurityScheme{
				Location: a2a.APIKeySecuritySchemeLocationHeader, Name: present.CredentialHeader,
				Description: "the caller's trstctl delegated credential (base64 DER), with its ID in " + present.CredentialIDHeader,
			},
		},
		SecurityRequirements: a2a.SecurityRequirementsOptions{{identityScheme: {}, delegationScheme: {}}},
	}
	raw, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("the agent key cannot sign")
	}
	kid, err := keyID(key.Public())
	if err != nil {
		return nil, err
	}
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{PrivateKey: key, KeyID: kid})
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	card.Signatures = []a2a.AgentCardSignature{*sig}
	return card, nil
}

// delegationInterceptor authorizes every message before the agent acts on it.
type delegationInterceptor struct {
	gate   *relying.Gate
	skills map[string]string
}

func (d *delegationInterceptor) Before(ctx context.Context, callCtx *a2asrv.CallContext, req *a2asrv.Request) (context.Context, any, error) {
	send, ok := req.Payload.(*a2a.SendMessageRequest)
	if !ok {
		return ctx, nil, fmt.Errorf("%w: only message/send is served", a2a.ErrUnauthorized)
	}
	skill := ""
	if send.Message != nil {
		skill, _ = send.Message.Metadata["skill"].(string)
	}
	tool, served := d.skills[skill]
	if !served {
		return ctx, nil, fmt.Errorf("%w: this agent does not serve skill %q", a2a.ErrUnauthorized, skill)
	}
	header := func(name string) string {
		values, _ := callCtx.ServiceParams().Get(name)
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	presentation := relying.PresentationFromHeaders(header(verifiedAgentHeader), header)
	if decision := d.gate.Authorize(ctx, presentation, tool); !decision.Allowed {
		return ctx, nil, fmt.Errorf("%w: %s", a2a.ErrUnauthorized, decision.Reason)
	}
	callCtx.User = &a2asrv.User{Name: presentation.AgentID, Authenticated: true}
	return ctx, nil, nil
}

func (d *delegationInterceptor) After(context.Context, *a2asrv.CallContext, *a2asrv.Response) error {
	return nil
}

// withAgentIdentity admits only connections whose verified certificate names an
// agent and hands that agent ID to the A2A handler.
func withAgentIdentity(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(verifiedAgentHeader)
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			http.Error(w, "an agent identity certificate is required", http.StatusUnauthorized)
			return
		}
		agent := agentFromCert(prefix, r.TLS.VerifiedChains[0][0])
		if agent == "" {
			http.Error(w, "the agent identity certificate names no agent", http.StatusForbidden)
			return
		}
		r.Header.Set(verifiedAgentHeader, agent)
		next.ServeHTTP(w, r)
	})
}

func agentFromCert(prefix string, cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if id := uri.String(); strings.HasPrefix(id, prefix) && len(id) > len(prefix) {
			return strings.TrimPrefix(id, prefix)
		}
	}
	return ""
}

func call(args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	cardURL := fs.String("card", "", "the serving agent's base URL")
	expect := fs.String("expect-agent", "", "the agent ID the serving agent's certificate must name")
	prefix := fs.String("agent-id-prefix", "spiffe://lab.trstctl.test/agent/", "the agent ID URI prefix")
	certFile := fs.String("tls-cert", "", "this agent's identity certificate (PEM)")
	keyFile := fs.String("tls-key", "", "this agent's identity key (PEM)")
	agentCA := fs.String("agent-ca", "", "the CA that issues agent identities (PEM)")
	credentialFile := fs.String("credential", "", "this agent's delegated credential (DER)")
	credentialID := fs.String("credential-id", "", "the delegated credential's ID")
	skill := fs.String("skill", "", "the skill to ask for")
	text := fs.String("text", "", "the task text")
	_ = fs.Parse(args)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(*agentCA) // #nosec G304 G703 -- operator-named CA file (CWE-22)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("the agent CA file holds no certificate")
	}
	peer := &peerKey{}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		// The serving agent's certificate names it by agent ID (a URI), not by host
		// name, so the chain and the ID are checked here instead of by host name.
		InsecureSkipVerify: true, // #nosec G402 -- VerifyConnection verifies the chain to the agent CA and the agent ID (CWE-295)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the serving agent presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return fmt.Errorf("the serving agent's certificate is not from the trusted agent CA: %w", err)
			}
			if agentFromCert(*prefix, leaf) != *expect {
				return fmt.Errorf("the serving agent is not %s", *expect)
			}
			peer.set(leaf.PublicKey)
			return nil
		},
	}
	credential, err := os.ReadFile(*credentialFile) // #nosec G304 G703 -- operator-named credential file (CWE-22)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: presentCredential{
		base:       &http.Transport{TLSClientConfig: tlsConfig},
		credential: base64.StdEncoding.EncodeToString(credential), id: *credentialID,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resolver := agentcard.NewResolver(httpClient)
	resolver.Verifier = a2acrypto.NewVerifier(a2acrypto.VerifierConfig{KeyResolver: a2acrypto.KeyResolverFunc(peer.resolve)})
	card, err := resolver.Resolve(ctx, *cardURL)
	if err != nil {
		return report(map[string]any{"error": "the serving agent's card was not accepted: " + err.Error()})
	}
	if len(card.Signatures) == 0 {
		return report(map[string]any{"error": "the serving agent's card is not signed"})
	}
	client, err := a2aclient.NewFromCard(ctx, card, a2aclient.WithJSONRPCTransport(httpClient))
	if err != nil {
		return err
	}
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(*text))
	msg.Metadata = map[string]any{"skill": *skill}
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: msg})
	if err != nil {
		return report(map[string]any{"card": card.Name, "error": err.Error()})
	}
	out := map[string]any{"card": card.Name}
	if reply, ok := result.(*a2a.Message); ok {
		out["reply"] = messageText(reply)
	} else {
		out["result"] = result
	}
	return report(out)
}

// peerKey holds the public key of the TLS peer this agent verified, the only key
// it accepts the serving agent's card signature from.
type peerKey struct {
	mu  sync.Mutex
	key crypto.PublicKey
}

func (p *peerKey) set(k crypto.PublicKey) {
	p.mu.Lock()
	p.key = k
	p.mu.Unlock()
}

func (p *peerKey) resolve(_ context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return nil, errors.New("no verified serving agent")
	}
	if got, err := keyID(p.key); err != nil || got != kid {
		return nil, errors.New("the card is not signed by the serving agent's certificate key")
	}
	return p.key, nil
}

func keyID(pub crypto.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}

func messageText(m *a2a.Message) string {
	if m == nil {
		return ""
	}
	var parts []string
	for _, p := range m.Parts {
		if p == nil {
			continue
		}
		if t, ok := p.Content.(a2a.Text); ok {
			parts = append(parts, string(t))
		}
	}
	return strings.Join(parts, " ")
}

type presentCredential struct {
	base       http.RoundTripper
	credential string
	id         string
}

func (p presentCredential) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(present.CredentialHeader, p.credential)
	clone.Header.Set(present.CredentialIDHeader, p.id)
	return p.base.RoundTrip(clone)
}

func report(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "a2aagent:", err)
	os.Exit(1)
}
