// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mongosignin"
	"trstctl.com/trstctl/internal/crypto/mysqlsignin"
	"trstctl.com/trstctl/internal/crypto/pgsignin"
	"trstctl.com/trstctl/internal/crypto/redissignin"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/sshgateway"
)

// SSHKeySigner is the part of the agent channel that certifies an SSH
// session's per-session key for the job the gateway holds (A254).
type SSHKeySigner interface {
	SignJobSSHKey(ctx context.Context, jobID int64, attempt int, publicKey []byte) ([]byte, error)
}

// Config wires a gateway to its agent channel and listener.
type Config struct {
	// Channel claims session jobs, redeems their credentials and reports.
	Channel relay.Channel
	// Listener accepts client connections (TLS, with the agent's certificate).
	Listener net.Listener
	// Dial reaches upstream targets; nil uses a plain dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
	// ClaimInterval paces the claim loop; ExtendInterval the lease extensions.
	ClaimInterval, ExtendInterval time.Duration
	// MaxSessions bounds the sessions held at once; MaxConnections the
	// connections per session.
	MaxSessions, MaxConnections int
	// Logf receives one line per refusal and session end; never credentials.
	Logf func(format string, args ...any)
}

// Gateway holds the sessions this agent serves.
type Gateway struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*session
	claimNow chan struct{}
	// sshHost is the host key SSH clients see, made with the first SSH
	// session and wiped when the gateway stops.
	sshHostOnce sync.Once
	sshHost     *sshgateway.HostKey
	sshHostErr  error
}

type session struct {
	intent   SessionIntent
	job      relay.Job
	material relay.Material
	// sshKey is an SSH session's certified per-session key.
	sshKey *sshgateway.SessionKey
	// recorder records the session when the control plane asks (A255).
	recorder *sessionRecorder
	// serving counts connections still being served; the session's
	// recording closes only after each has flushed.
	serving sync.WaitGroup
	destroy func()
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	served  int
	ended   chan struct{}
	endOnce sync.Once
	reason  string
}

// New builds a gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.Channel == nil || cfg.Listener == nil {
		return nil, errors.New("accessgateway: a channel and a listener are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ClaimInterval <= 0 {
		cfg.ClaimInterval = 2 * time.Second
	}
	if cfg.ExtendInterval <= 0 {
		cfg.ExtendInterval = 10 * time.Second
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 16
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		cfg.Dial = d.DialContext
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Gateway{cfg: cfg, sessions: map[string]*session{}, claimNow: make(chan struct{}, 1)}, nil
}

// Run serves until ctx ends: it claims sessions and accepts connections.
// Every held session ends with ctx, its connections closed and its
// credential wiped.
func (g *Gateway) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.claimLoop(ctx)
	}()
	go func() {
		<-ctx.Done()
		_ = g.cfg.Listener.Close()
	}()
	for {
		conn, err := g.cfg.Listener.Accept()
		if err != nil {
			cancel()
			wg.Wait()
			g.endAll("gateway stopped")
			if g.sshHost != nil {
				g.sshHost.Destroy()
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go g.serve(ctx, conn)
	}
}

// Sessions reports the session IDs held now (for tests and status).
func (g *Gateway) Sessions() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.sessions))
	for id := range g.sessions {
		out = append(out, id)
	}
	return out
}

func (g *Gateway) claimLoop(ctx context.Context) {
	ticker := time.NewTicker(g.cfg.ClaimInterval)
	defer ticker.Stop()
	for {
		g.claim(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-g.claimNow:
		}
	}
}

func (g *Gateway) claim(ctx context.Context) {
	g.mu.Lock()
	room := g.cfg.MaxSessions - len(g.sessions)
	g.mu.Unlock()
	if room <= 0 {
		return
	}
	jobs, err := g.cfg.Channel.ClaimJobs(ctx, ClaimableKinds(), room, int((2*g.cfg.ExtendInterval)/time.Second)+5)
	if err != nil {
		g.cfg.Logf("accessgateway: claim: %v", err)
		return
	}
	for _, job := range jobs {
		g.start(ctx, job)
	}
}

func (g *Gateway) start(ctx context.Context, job relay.Job) {
	var intent SessionIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || ValidateSessionIntent(intent) != nil {
		g.report(ctx, job, relay.OutcomeFailed, "job payload is not a gateway session")
		return
	}
	if !g.cfg.Now().Before(intent.ExpiresAt) {
		g.report(ctx, job, relay.OutcomeFailed, sessionReport(intent.SessionID, "deadline", 0))
		return
	}
	if intent.TargetType == TargetSSH {
		key, err := g.certifySessionKey(ctx, job)
		if err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", intent.SessionID, err)
			g.report(ctx, job, relay.OutcomeFailed, sessionReport(intent.SessionID, "credential_unavailable", 0))
			return
		}
		g.holdSession(ctx, &session{intent: intent, job: job, sshKey: key, destroy: key.Destroy,
			recorder: g.recorderFor(ctx, intent, job), conns: map[net.Conn]struct{}{}, ended: make(chan struct{})})
		return
	}
	items, err := g.cfg.Channel.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		g.report(ctx, job, relay.OutcomeFailed, sessionReport(intent.SessionID, "credential_unavailable", 0))
		return
	}
	material, destroy, err := relay.AdoptMaterial(items)
	if err != nil || len(material[intent.CredentialRef]) == 0 {
		if destroy != nil {
			destroy()
		}
		g.report(ctx, job, relay.OutcomeFailed, sessionReport(intent.SessionID, "credential_unavailable", 0))
		return
	}
	// The session's own password is masked wherever it shows up.
	var secrets [][]byte
	switch intent.TargetType {
	case TargetPostgres:
		if target, err := pgsignin.ParseDSN(material[intent.CredentialRef]); err == nil {
			secrets = append(secrets, append([]byte(nil), target.Password...))
			target.Wipe()
		}
	case TargetRedis:
		if target, err := redissignin.ParseURL(material[intent.CredentialRef]); err == nil {
			secrets = append(secrets, append([]byte(nil), target.Password...))
			target.Wipe()
		}
	case TargetMySQL:
		if target, err := mysqlsignin.ParseDSN(material[intent.CredentialRef]); err == nil {
			secrets = append(secrets, append([]byte(nil), target.Password...))
			target.Wipe()
		}
	case TargetMongo:
		if target, err := mongosignin.ParseURI(material[intent.CredentialRef]); err == nil {
			secrets = append(secrets, append([]byte(nil), target.Password...))
			target.Wipe()
		}
	}
	g.holdSession(ctx, &session{intent: intent, job: job, material: material, destroy: destroy,
		recorder: g.recorderFor(ctx, intent, job, secrets...), conns: map[net.Conn]struct{}{}, ended: make(chan struct{})})
	for _, b := range secrets {
		secret.Wipe(b)
	}
}

// recorderFor starts a session's recording when the control plane asks for
// one and the channel can take it; nil records nothing.
func (g *Gateway) recorderFor(ctx context.Context, intent SessionIntent, job relay.Job, secrets ...[]byte) *sessionRecorder {
	uploader, ok := g.cfg.Channel.(RecordingUploader)
	if !intent.Record || !ok {
		return nil
	}
	return newSessionRecorder(ctx, uploader, job, g.cfg.Now, secrets...)
}

// holdSession registers a started session and holds it, unless the session is
// held already (its earlier claim is still live).
func (g *Gateway) holdSession(ctx context.Context, s *session) {
	g.mu.Lock()
	if _, held := g.sessions[s.intent.SessionID]; held {
		g.mu.Unlock()
		if s.recorder != nil {
			s.recorder.abandon()
		}
		s.destroy()
		return
	}
	g.sessions[s.intent.SessionID] = s
	g.mu.Unlock()
	go g.hold(ctx, s)
}

// certifySessionKey makes an SSH session's key and has the control plane
// certify it for this job attempt. The key never leaves this process.
func (g *Gateway) certifySessionKey(ctx context.Context, job relay.Job) (*sshgateway.SessionKey, error) {
	signer, ok := g.cfg.Channel.(SSHKeySigner)
	if !ok {
		return nil, errors.New("the agent channel cannot certify SSH session keys")
	}
	key, err := sshgateway.NewSessionKey()
	if err != nil {
		return nil, err
	}
	certificate, err := signer.SignJobSSHKey(ctx, job.JobID, job.Attempt, key.PublicKey())
	if err != nil {
		key.Destroy()
		return nil, fmt.Errorf("certify the session key: %w", err)
	}
	if _, err := key.Certify(certificate); err != nil {
		key.Destroy()
		return nil, err
	}
	return key, nil
}

func (g *Gateway) hostKey() (*sshgateway.HostKey, error) {
	g.sshHostOnce.Do(func() { g.sshHost, g.sshHostErr = sshgateway.NewHostKey() })
	return g.sshHost, g.sshHostErr
}

// hold keeps the session's lease until its deadline or until the control
// plane recalls it (revocation), then ends it and reports.
func (g *Gateway) hold(ctx context.Context, s *session) {
	deadline := time.NewTimer(s.intent.ExpiresAt.Sub(g.cfg.Now()))
	defer deadline.Stop()
	extend := time.NewTicker(g.cfg.ExtendInterval)
	defer extend.Stop()
	reason := "deadline"
loop:
	for {
		select {
		case <-ctx.Done():
			reason = "gateway stopped"
			break loop
		case <-deadline.C:
			break loop
		case <-extend.C:
			if g.extend(ctx, s.job) {
				reason = "recalled"
				break loop
			}
		}
	}
	g.end(s, reason)
	if reason != "gateway stopped" {
		g.report(context.WithoutCancel(ctx), s.job, relay.OutcomeExecuted, sessionReport(s.intent.SessionID, reason, s.servedCount()))
	}
}

// extend renews a held session's lease and reports whether the control plane
// has withdrawn it (a revoked session's job is recalled). A transient error
// keeps the session: its lease still covers the next attempt, and the native
// deadline bounds it regardless.
func (g *Gateway) extend(ctx context.Context, job relay.Job) bool {
	if ext, ok := g.cfg.Channel.(relay.JobLeaseMaintainer); ok {
		_, err := ext.ExtendJobClaim(ctx, job.JobID, job.Attempt)
		return errors.Is(err, relay.ErrJobClaimLost)
	}
	accepted, err := g.cfg.Channel.ReportJobResult(ctx, job.JobID, job.Attempt, "extend", "", "")
	return err == nil && !accepted
}

func (g *Gateway) end(s *session, reason string) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		s.reason = reason
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		close(s.ended)
		if s.recorder != nil {
			// Each connection flushes its recording as it closes; then the
			// last chunk goes up, before the session reports.
			waitAtMost(&s.serving, 15*time.Second)
			s.recorder.close()
		}
		s.destroy()
		g.mu.Lock()
		delete(g.sessions, s.intent.SessionID)
		g.mu.Unlock()
		g.cfg.Logf("accessgateway: session %s ended: %s", s.intent.SessionID, reason)
	})
}

func (g *Gateway) endAll(reason string) {
	g.mu.Lock()
	held := make([]*session, 0, len(g.sessions))
	for _, s := range g.sessions {
		held = append(held, s)
	}
	g.mu.Unlock()
	for _, s := range held {
		g.end(s, reason)
	}
}

func (g *Gateway) report(ctx context.Context, job relay.Job, outcome, detail string) {
	if _, err := g.cfg.Channel.ReportJobResult(ctx, job.JobID, job.Attempt, outcome, detail, ""); err != nil {
		g.cfg.Logf("accessgateway: report job %d: %v", job.JobID, err)
	}
}

func sessionReport(id, ended string, connections int) string {
	raw, _ := json.Marshal(SessionReport{SessionID: id, Ended: ended, Connections: connections})
	return string(raw)
}

func (s *session) servedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.served
}

// lookup finds a held session, asking the claim loop for one immediate pass
// when the session is not held yet (the requester may connect before the
// next tick).
func (g *Gateway) lookup(ctx context.Context, id string) *session {
	for attempt := 0; attempt < 15; attempt++ {
		g.mu.Lock()
		s := g.sessions[id]
		g.mu.Unlock()
		if s != nil {
			return s
		}
		select {
		case g.claimNow <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

// serve admits one client connection: the preface names the session and
// carries its ticket; nothing else is read before the ticket matches.
func (g *Gateway) serve(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	line, err := readPreface(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 3 || fields[0] != Preface {
		g.deny(conn, "malformed preface")
		return
	}
	s := g.lookup(ctx, fields[1])
	switch {
	case s == nil:
		g.deny(conn, "unknown session")
		return
	case !TicketMatches(fields[2], s.intent.TicketDigest):
		g.deny(conn, "ticket refused")
		return
	case !g.cfg.Now().Before(s.intent.ExpiresAt):
		g.deny(conn, "session expired")
		return
	}
	var host *sshgateway.HostKey
	answer := "OK\n"
	if s.intent.TargetType == TargetSSH {
		var err error
		if host, err = g.hostKey(); err != nil {
			g.deny(conn, "the gateway has no SSH host key")
			return
		}
		// The client's tunnel verified this gateway over TLS; the host key it
		// learns here is the one its SSH client is told to expect.
		answer = "OK " + host.AuthorizedKey() + "\n"
	}
	if !s.admit(conn, g.cfg.MaxConnections) {
		g.deny(conn, "session ended or at its connection limit")
		return
	}
	defer s.release(conn)
	var rec *connRecorder
	if s.recorder != nil {
		rec = s.recorder.connection()
		defer rec.close()
	}
	if _, err := conn.Write([]byte(answer)); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(s.intent.ExpiresAt)
	switch s.intent.TargetType {
	case TargetPostgres:
		dsn := s.credential()
		defer secret.Wipe(dsn)
		if err := servePostgres(ctx, conn, dsn, s.intent.ExpiresAt, g.cfg.Dial, rec); err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", s.intent.SessionID, err)
		}
	case TargetRedis:
		credential := s.credential()
		defer secret.Wipe(credential)
		if err := serveRedis(ctx, conn, credential, s.intent.ExpiresAt, g.cfg.Dial, rec); err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", s.intent.SessionID, err)
		}
	case TargetMySQL:
		dsn := s.credential()
		defer secret.Wipe(dsn)
		if err := serveMySQL(ctx, conn, dsn, s.intent.ExpiresAt, g.cfg.Dial, rec); err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", s.intent.SessionID, err)
		}
	case TargetMongo:
		uri := s.credential()
		defer secret.Wipe(uri)
		if err := serveMongo(ctx, conn, uri, s.intent.ExpiresAt, g.cfg.Dial, rec); err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", s.intent.SessionID, err)
		}
	case TargetSSH:
		if err := sshgateway.Serve(ctx, conn, host, s.sshKey, sshgateway.Upstream{Address: s.intent.SSHAddress,
			User: s.intent.SSHPrincipal, HostKeyFingerprints: s.intent.SSHHostKeyFingerprints, Dial: g.cfg.Dial}, sshRecorder(rec)); err != nil {
			g.cfg.Logf("accessgateway: session %s: %v", s.intent.SessionID, err)
		}
	}
	_ = conn.Close()
}

func (g *Gateway) deny(conn net.Conn, reason string) {
	g.cfg.Logf("accessgateway: connection from %s refused: %s", conn.RemoteAddr(), reason)
	_, _ = fmt.Fprintf(conn, "DENY %s\n", reason)
	_ = conn.Close()
}

func (s *session) admit(conn net.Conn, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.ended:
		return false
	default:
	}
	if len(s.conns) >= limit {
		return false
	}
	s.conns[conn] = struct{}{}
	s.served++
	s.serving.Add(1)
	return true
}

func (s *session) release(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.serving.Done()
}

// sshRecorder hands the SSH relay a connection's recorder, or none.
func sshRecorder(rec *connRecorder) sshgateway.Recorder {
	if rec == nil {
		return nil
	}
	return rec
}

// waitAtMost waits for wg, but not longer than d.
func waitAtMost(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// credential copies the session's upstream credential for one connection;
// the caller wipes the copy.
func (s *session) credential() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.material[s.intent.CredentialRef]...)
}

// readPreface reads the preface line byte by byte, so nothing the client sends
// after it (its first protocol message) is buffered away from the session.
func readPreface(conn net.Conn) (string, error) {
	var b strings.Builder
	one := make([]byte, 1)
	for b.Len() < maxPrefaceBytes {
		if _, err := conn.Read(one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return b.String(), nil
		}
		b.WriteByte(one[0])
	}
	return "", errors.New("accessgateway: preface too long")
}
